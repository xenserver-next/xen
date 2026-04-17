/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Wrapper around xen/common/page_alloc.c for the allocator test framework.
 *
 * The test framework includes the real page_alloc.c directly in its
 * translation unit, together with mocks for the Xen types and functions it
 * uses and helper code for NUMA heap initialisation and heap-state checks.
 *
 * This file provides the definitions needed for that setup. It also wraps
 * selected page_alloc.c entry points, such as mark_page_offline() and
 * offline_page(), so test scenarios can log allocator actions and resulting
 * state during execution.
 *
 * Copyright (C) 2026 Cloud Software Group
 */
#ifndef TOOLS_TESTS_ALLOC_PAGE_ALLOC_WRAPPER_H
#define TOOLS_TESTS_ALLOC_PAGE_ALLOC_WRAPPER_H

// To be enabled by tests testing code in xen/common/sysctl.c
// #define TEST_WRAP_XEN_COMMON_SYSCTL_C

// To be enabled by tests testing code in xen/common/memory.c
// #define TEST_WRAP_XEN_COMMON_MEMORY_C

/* If sysctl.c is included, enable CONFIG_SYSCTL for it dependencies */
#if defined(TEST_WRAP_XEN_COMMON_SYSCTL_C)
#define CONFIG_SYSCTL 1
#endif

/* For now, we always include page_alloc.c (it's a dependency) */
#define TEST_WRAP_XEN_COMMON_PAGE_ALLOC_C
#include "page-alloc-shim.h"

/* Include the real page_alloc.c for testing */
#pragma GCC diagnostic push
/* At a later point, fix the remaining sign-compare warnings in page_alloc.c */
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"
/*
 * Instrumenting the BUG() macro asserting to hit it means it is no longer
 * noreturn, and a function expects it to be noreturn, so disable this warning
 */
#pragma GCC diagnostic ignored "-Wreturn-type"

void *alloc_xenheap_pages(unsigned int order, unsigned int memflags);
void  init_domheap_pages(paddr_t ps, paddr_t pe);
struct page_info *alloc_domheap_pages(struct domain *d, unsigned int order,
                                      unsigned int memflags);

#include "../../xen/common/page_alloc.c"
#pragma GCC diagnostic pop

#ifdef TEST_WRAP_XEN_COMMON_DOMCTL_C
#include "domctl-proxy.h"
#endif

#ifdef TEST_WRAP_XEN_COMMON_MEMORY_C
#include "memory-proxy.h"
#endif

#ifdef TEST_WRAP_XEN_COMMON_SYSCTL_C
#include "sysctl-proxy.h"
#endif

/* Allow the logging spinlock mocks to identify the allocator heap lock. */
static spinlock_t *heap_lock_ptr = &heap_lock;

/* Backing storage for the synthetic allocator state used by the tests. */
#ifndef PAGES_PER_ZONE
#define PAGES_PER_ZONE 8
#endif

#ifndef MAX_PAGES
#define MAX_PAGES (MAX_NUMNODES * NR_ZONES * PAGES_PER_ZONE)
#endif

/*
 * The synthetic frame table backs the page_info entries used by the tests.
 * It is indexed by MFN so helper code and the imported allocator can
 * translate directly between MFNs and page_info pointers.
 */
struct page_info frame_table[MAX_PAGES];

/* Convenience pointer used by test scenarios. */
static struct page_info *test_pages = frame_table;

#define TOTAL_CLAIMS ((unsigned long)outstanding_claims)
#define FREE_PAGES \
        avail_heap_pages(MEMZONE_XEN + 1, NR_ZONES - 1, -1)

#define DOM_GENERIC_CLAIMS(d) ((d)->outstanding_pages - (d)->node_claims)
#define DOM_NODE_CLAIMS(d, n) ((d)->claims[n])
#endif
