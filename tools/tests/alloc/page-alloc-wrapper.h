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

#define TEST_WRAP_XEN_COMMON_PAGE_ALLOC_C
#include "page-alloc-shim.h"

#ifdef TEST_WRAP_XEN_COMMON_DOMCTL_C
#include "domctl-shim.h"
#endif

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
#include "../../xen/common/page_alloc.c"
#pragma GCC diagnostic pop

#ifdef TEST_WRAP_XEN_COMMON_DOMCTL_C
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "../../xen/common/domctl.c"
#pragma GCC diagnostic pop

/*
 * Provide dispatch proxies to call the do_domctl() hypercall handler
 * for test scenarios to install memory claims using the do_domctl(),
 * which is the real consumer of the XEN_DOMCTL_claim_memory command.
 */

/* Harness to call the do_domctl hypercall handler directly */
int xc_domain_claim_memory_harness(uint32_t domid, uint32_t *nr_entries,
                                   memory_claim_t *claim_set, uint32_t mode)
{
    struct xen_domctl_claim_memory uinfo = {
        .claim_set = { claim_set },
        .nr_entries = *nr_entries,
        .mode = mode,
    };
    xen_domctl_t domctl = {
        .interface_version = XEN_DOMCTL_INTERFACE_VERSION,
        .cmd = XEN_DOMCTL_claim_memory,
        .domain = domid,
        .u.claim_memory = uinfo,
    };
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) handle;

    set_xen_guest_handle(handle, &domctl);
    int ret = do_domctl(handle);
    if ( !ret )
        *nr_entries = handle.p->u.claim_memory.nr_entries;
    return ret;
}

int xc_domain_claim_memory_proxy(struct domain *d, uint32_t nr,
                                 memory_claim_t *claim_set)
{
    return xc_domain_claim_memory_harness(d->domain_id, &nr, claim_set, 0);
}

/* Install a generic claim set using the do_domctl hypercall handler */
int xc_domain_claim_memory_unpinned_proxy(struct domain *d, unsigned long pages)
{
    memory_claim_t claim_set[] = {
        { .target = XEN_DOMCTL_CLAIM_MEMORY_UNPINNED, .pages = pages },
    };

    return xc_domain_claim_memory_proxy(d, ARRAY_SIZE(claim_set), claim_set);
}

int xc_domain_get_memory_claims_proxy(struct domain *d, uint32_t *nr,
                                      memory_claim_t *claim_set)
{
    return xc_domain_claim_memory_harness(d->domain_id, nr, claim_set, 1);
}

#endif /* TEST_WRAP_XEN_COMMON_DOMCTL_C */

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
