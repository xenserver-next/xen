 /* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tests using offline_page() to verify reserve_offlined_page()
 *
 * The workflow tested here is offlining a free page:
 *
 * 1. offline_page() calls mark_page_offlined() to mark the page.
 * 2. It calls reserve_heap_page() to find the containing buddy.
 * 3. It calls reserve_offlined_page() to reserve the marked pages within
 *    that buddy.
 *
 * reserve_offlined_page() then:
 *
 * 1. Removes the buddy, a 2^order group of pages, from the free list.
 * 2. Finds size-aligned spans of healthy pages within it.
 * 3. Rebuilds healthy buddies from those spans and
 *    adds them back to the free list via page_list_add_scrub().
 * 4. Moves offlined subpages to the offlined page lists.
 *
 * Another workflow marks an in-use page for offlining and then
 * relies on free_heap_pages() to call reserve_offlined_page()
 * when that page is eventually freed.
 *
 * Copyright (C) 2026 Cloud Software Group
 */
#define TEST_ENABLE_XC_DOMAIN_C
#include "harness/native.h"

/* Test merging a surviving tail pair into an order-1 buddy. */
static void test_merge_tail_pair(int start_mfn)
{
    struct page_info *pages = frame_table + start_mfn;
    uint32_t status = 0;

    /* Seed a single order-2 buddy onto the heap. */
    test_page_list_add_buddy(pages, order2);
    /* Mark the fourth page dirty to verify dirty-state preservation. */
    pages[3].count_info |= PGC_need_scrub;
    pages[0].u.free.first_dirty = 3;

    /* Act: Offline the second page. */
    ASSERT(offline_page(page_to_mfn(pages + 1), 0, &status) == 0);
    ASSERT(status & PG_OFFLINE_OFFLINED);
    ASSERT(FREE_PAGES == 3);

    /*
     * Offlining page 1 results in splitting the original order-2 buddy into:
     * - page[0] as an order-0 buddy
     * - page[1] is the offlined page, removed from the free list
     *
     * As [2] [3] are aligned, they are merged into an order-1 buddy.
     * - page[2] as an order-1 head page of a buddy with page[3] as its tail
     */
    CHECK(PFN_ORDER(&pages[0]) == 0, "Former head page, now order-0");
    CHECK(PFN_ORDER(&pages[1]) == 0, "Offlined page should be order-0");
    /* pages[0] and pages[1] were prepared as clean pages and still are. */
    ASSERT(pages[0].u.free.first_dirty == INVALID_DIRTY_IDX);
    ASSERT(pages[1].u.free.first_dirty == INVALID_DIRTY_IDX);

    /* The tail pair is expected to be merged into one order-1 buddy. */
    CHECK(PFN_ORDER(&pages[2]) == 1,
        "The pair of tail pages should be merged into an order-1 buddy");
    CHECK(pages[2].u.free.first_dirty == 1, "In tail buddy, the 2nd is dirty");
    /* The tail page of the merged buddy does not use first_dirty. */
    CHECK(pages[3].u.free.first_dirty == INVALID_DIRTY_IDX,
          "Tail page of the merged buddy should not set first_dirty");
}

int main(int argc, char *argv[])
{
    const char *topic = "Integration test of offline_page()";
    if ( !parse_args(argc, argv, topic) )
        return EXIT_FAILURE;

    init_page_alloc_tests();
    RUN_TESTCASE("TMTP", test_merge_tail_pair, 4);
    return test_complete();
}
