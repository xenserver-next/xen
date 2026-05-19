/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Regression test offlining to not return misaligned buddies to free lists.
 * Copyright (C) 2026 Cloud Software Group
 */
#include "harness/native.h"

/*
 * Verify that offlining the head page of an order-2 buddy does not return
 * a misaligned buddy to the free list, and the pages returned to the free
 * list are usable for allocations.
 */
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
    test_page_list_add_buddy(pg, order2);

    /* Act */
    offline_page(page_to_mfn(pg), 0, &status);
    CHECK(status & PG_OFFLINE_OFFLINED, "Page should be offlined");

    /*
     * The expected free list state after offlining the buddy head is:
     * +---------------+---------------+----------------+---------------+
     * | offlined page |  single page  |    head page with a tail page  |
     * +---------------+---------------+----------------+---------------+
     */
    CHECK(page_aligned(pg + 1), "The buddy #%lu is not aligned to order-%d",
          mfn_x(page_to_mfn(pg + 1)), PFN_ORDER(pg + 1));

    /* Allocate and free a page to trigger buddy merging on free. */
    free_domheap_pages(alloc_domheap_pages(dom1, order0, 0), order0);
    CHECK((pg = alloc_domheap_pages(dom1, order1, 0)), "Alloc the order-1 pg");

    /* Inspect the predecessor (pg is the tail of the unaligned buddy) */
    CHECK(page_aligned(pg - 1), "The buddy #%lu is not aligned to order-%d!",
          mfn_x(page_to_mfn(pg - 1)), PFN_ORDER(pg - 1));

    /* Test allocating the remaining page */
    alloc_domheap_pages(dom1, order0, 0);
}

int main(int argc, char *argv[])
{
    if ( !parse_args(argc, argv, "Test offlining to return aligned buddies") )
        return EXIT_FAILURE;

    init_page_alloc_tests();
    RUN_TESTCASE("TUBM", test_unaligned_buddy_merge, 4);

    return test_complete();
}
