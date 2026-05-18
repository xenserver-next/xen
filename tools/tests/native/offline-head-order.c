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
 * Copyright (C) 2026 Cloud Software Group
 */
#define TEST_ENABLE_XC_DOMAIN_C
#include "harness/native.h"

static void test_offline_head_order(int start_mfn)
{
    struct page_info *page = frame_table + start_mfn;
    uint32_t status = 0;

    /* Seed a single order-1 buddy onto the heap. */
    test_page_list_add_buddy(page, order1);
    ASSERT(PFN_ORDER(page) == 1);
    /* Offline the head page. */
    ASSERT(offline_page(page_to_mfn(page), 0, &status) == 0);
    ASSERT(status == PG_OFFLINE_OFFLINED);

    /* Confirm the status of the page as status offlined. */
    status = 0;
    ASSERT(query_page_offline(page_to_mfn(page), &status) == 0);
    ASSERT(status == PG_OFFLINE_STATUS_OFFLINED);

    /* Check the order of the offlined head page. */
    EXPECT_FAIL_BEGIN(); /* PFN_ORDER(page) should 0, but is still 1 */
    ASSERT(PFN_ORDER(page) == 0);
    EXPECT_FAIL_END(1);

    /*
     * Allocate the successor page of the offlined page. This prevents
     * the normal successor page merge when the page is re-onlined below.
     */
    struct page_info *pg = alloc_domheap_pages(dom1, order0, 0);
    ASSERT(pg == page + 1);
    ASSERT(FREE_PAGES == 0);

    /*
     * The order of the split head page is still 1. Online the page again to
     * confirm that onlining it causes the order to be corrected to 0.
     */
    ASSERT(PFN_ORDER(page) == 1);

    /* Online the offlined former head page. */
    ASSERT(online_page(page_to_mfn(page), &status) == 0);
    ASSERT(status & PG_ONLINE_ONLINED);
    ASSERT(FREE_PAGES == 1);

    /*
     * In order to prevent corruption of the heap's free list, the offlined
     * former head page must be added back to the free list as an order-0 page,
     * even if it was previously the head of an order-1 buddy.
     *
     * This is because the successor page of the offlined head page is still
     * allocated and thus cannot be merged back into a higher-order buddy.
     *
     * If the offlined head page were added back to the free list with its
     * original order of 1, it could corrupt the heap's free list and could
     * lead to a Xen panic.
     *
     * Currently, this works because online_page() calls free_heap_pages()
     * with a hard-coded order of 0, which page_list_add_scrub() and passes
     * to page_list_add_scrub() and causes it to fix the page's order to 0
     * before inserting it onto the free list.
     *
     * It ensures that the free page accounting and free list remains correct.
     * Assert this as a regression test to ensure future changes are correct.
     */
    ASSERT(PFN_ORDER(page) == 0);
}

int main(int argc, char *argv[])
{
    const char *topic = "Test offlined head page to be updated to PFN_ORDER 0";
    if ( !parse_args(argc, argv, topic) )
        return EXIT_FAILURE;

    init_page_alloc_tests();
    RUN_TESTCASE("TOHP", test_offline_head_order, 2);
    return test_complete();
}
