/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Test that offlining a predecessor of pages that must not be merged
 * into an unaligned buddy is handled correctly. Specifically, verify
 * that the Xen page allocator does not merge such unaligned buddies
 * back onto the free list, which can produce a chain of events that
 * leads to a Xen panic after a few allocations and frees.
 *
 * This test reproduces the scenario in isolation by offlining a page
 * with an even MFN that has more than two following tail pages.
 *
 * If an unaligned buddy is returned to the free list, a sequence of
 * allocations and a subsequent free can corrupt the free list state
 * so that a later allocation triggers BUG() and crashes the instance.
 * The test checks the free list behavior and, if the bug is present,
 * confirms the resulting BUG().
 *
 * Copyright (C) 2026 Cloud Software Group
 */

/*
 * Include the main test library that sets up scenarios, asserts
 * allocator state, and provides the definitions and shims needed
 * to call the Xen page allocator code in this test program.
 */
#define TEST_ENABLE_XC_DOMAIN_C
#include "harness/native.h"

/* Verify the behavior of buddy merging after offlining a page */
static void test_unaligned_buddy_merge(int start_mfn)
{
    struct page_info *pg = frame_table + start_mfn;
    uint32_t status = 0;

    /*
     * Prepare a valid order-2 buddy (4 pages) with this layout:
     * +---------------+-----------------+-----------------+----------------+
     * | head page     | tail page 1     | tail page 2     | tail page 3    |
     * +---------------+-----------------+-----------------+----------------+
     */
    test_page_list_add_buddy(pg, order2); /* Seed the heap with this buddy */

    /* Act */
    offline_page(page_to_mfn(pg), 0, &status);
    CHECK(status & PG_OFFLINE_OFFLINED, "Page should be offlined");

    /*
     * The correct free list state after offlining the head page of the buddy
     * is the the healthy pages are merged back onto the free list using a
     * single page and a size-aligned buddy of the remaining pages:
     * +---------------+-----------------+-----------------+----------------+
     * | offlined page | single page     |    head page with a tail page    |
     * +---------------+-----------------+-----------------+----------------+
     */
    CHECK(page_aligned(pg + 1), "The buddy #%lu is not aligned to order-%d",
          mfn_x(page_to_mfn(pg + 1)), PFN_ORDER(pg + 1));

    /* Allocate and free a page to trigger buddy merging on free. */
    free_domheap_pages(alloc_domheap_pages(dom1, order0, 0), order0);
    CHECK((pg = alloc_domheap_pages(dom1, order1, 0)), "Alloc the order-1 pg");

    /* Inspect the predecessor (pg is the tail of the unaligned buddy) */
    CHECK(page_aligned(pg - 1), "The buddy #%lu is not aligned to order-%d!",
          mfn_x(page_to_mfn(pg - 1)), PFN_ORDER(pg - 1));

    /* Allocate the remaining page; a clean heap should not hit BUG(). */
    alloc_domheap_pages(dom1, order0, 0); /* Triggers BUG() */
}

int main(int argc, char *argv[])
{
    if ( !parse_args(argc, argv, "Test not growing unaligned buddies") )
        return EXIT_FAILURE;

    init_page_alloc_tests();
    RUN_TESTCASE("TUBM", test_unaligned_buddy_merge, 4);

    return test_complete();
}
