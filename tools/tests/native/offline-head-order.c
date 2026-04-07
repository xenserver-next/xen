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
#include "harness/native.h"

static void test_offline_head_order(int start_mfn)
{
    struct page_info *page = frame_table + start_mfn;
    uint32_t status = 0;

    /* Seed a single order-1 buddy onto the heap. */
    test_page_list_add_buddy(page, order1);
    /* Offline the head page. */
    ASSERT(offline_page(page_to_mfn(page), 0, &status) == 0);
    ASSERT(status & PG_OFFLINE_OFFLINED);
    /* The tail page should be split as a single order-0 buddy. */
    ASSERT(PFN_ORDER(page + 1) == 0);
    ASSERT(FREE_PAGES == 1);

    /* If the single alone page would be onlined again, needs to be order 0! */
    CHECK(PFN_ORDER(page) == 0, "BUG: Split offlined head page needs order 0");
}

int main(int argc, char *argv[])
{
    const char *topic = "Test split offlined head page to be order 0";
    if ( !parse_args(argc, argv, topic) )
        return EXIT_FAILURE;

    init_page_alloc_tests();
    RUN_TESTCASE("TOHP", test_offline_head_order, 2);
    return test_complete();
}
