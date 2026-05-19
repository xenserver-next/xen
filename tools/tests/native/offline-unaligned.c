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
#include "harness/common.h"

/* test_bss_start must be first in the BSS segment */
void __aligned(PAGE_SIZE) *test_bss_start;

/* Include xen/mm.h so we can wrap page_list_del() to assert the corruption. */
#define TEST_WRAP_XEN_INCLUDE_XEN_MM_H
#include "harness/mm-wrapper.h"

static bool expect_free_list_corruption;

/*
 * Wrap page_list_del() to not fail the test by virtue of the prepared
 * free list state but continue the test like a running Xen instance
 * would in many cases. Assert and expect the corruption, and continue.
 */
static inline void wrap_page_list_del(struct page_info *page,
                                      struct page_list_head *head)
{
    printf("page_list_del: page MFN %lu, order %u\n",
           mfn_x(page_to_mfn(page)), PFN_ORDER(page));

    if ( expect_free_list_corruption )
        EXPECT_FAIL_BEGIN();
    CHECK(page->list.next && page->list.prev, "The free list is corrupt now!");
    if ( expect_free_list_corruption )
        EXPECT_FAIL_END(1);

    if ( page->list.next && page->list.prev )
        page_list_del(page, head);
}
#define page_list_del(page, head) wrap_page_list_del(page, head)

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
    EXPECT_FAIL_BEGIN();
    /*
     * Due to a bug in reserve_offlined_page(), we get an unaligned buddy:
     * +---------------+-----------------+-----------------+----------------+
     * | offlined page |     head page with a tail page    | single page    |
     * +---------------+-----------------+-----------------+----------------+
     */
    CHECK(page_aligned(pg + 1), "The buddy #%lu is not aligned to order-%d",
          mfn_x(page_to_mfn(pg + 1)), PFN_ORDER(pg + 1));
    EXPECT_FAIL_END(1);

    /* Allocate and free a page to trigger buddy merging on free. */

    /*
     * After allocating and freeing MFN 7, we get a double-freed MFN 6 due
     * to aligned predecessor merging in free_heap_pages():
     *
     *         MFN 4             MFN 5             MFN 6            MFN 7
     *   +---------------+-----------------+-----------------+
     *   | offlined page |    head page         tail page    |
     *   |               |       Unaligned buddies are       |
     *   |               |      an invariant violation!      |
     *   +---------------+-----------------+-----------------+----------------+
     *                                     |    head page        tail page    |
     *                                     +-----------------+----------------+
     */
    expect_free_list_corruption = true;
    free_domheap_pages(alloc_domheap_pages(dom1, order0, 0), order0);

    /*
     * At this point, the free list is already corrupt. In free_heap_pages(),
     * the tail of the unaligned buddy was added to the free list a 2nd time
     * as the page of an overlapping aligned buddy. This is per design of the
     * algorithm: These pages are free and thus the merging occurs as expected.
     *
     * The next allocation allocates the tail of the unaligned buddy, which
     * is now, due to the merge, also the head of the new aligned buddy.
     */
    CHECK((pg = alloc_domheap_pages(dom1, order1, 0)), "Alloc the order-1 pg");

    /* Inspect the predecessor (pg is the tail of the unaligned buddy) */
    EXPECT_FAIL_BEGIN();
    /*
     * After allocating two more pages, MFN 6 is free AND in-use:
     *
     *         MFN 4             MFN 5             MFN 6            MFN 7
     *   +---------------+-----------------+-----------------+
     *   | offlined page |    head page         tail page    |
     *   +---------------+-----------------+-----------------+----------------+
     *                                     |    in-use page      in-use page  |
     *                                     +-----------------+----------------+
     */
    CHECK(page_aligned(pg - 1), "The buddy #%lu is not aligned to order-%d!",
          mfn_x(page_to_mfn(pg - 1)), PFN_ORDER(pg - 1));
    EXPECT_FAIL_END(1);

    /* Allocate the remaining page; a clean heap should not hit BUG(). */
    testcase_assert_expect_to_hit_bug = true;
    /*
     * As described above, if pg is the tail of an unaligned order-1 buddy,
     * the unaligned buddy is still on the free list and this allocation will
     * remove it from the free list and check alloc_heap_pages() checks the
     * buddies to have a reference count of zero, and the already allocated
     * page is returned as the tail of the unaligned buddy, causing the BUG().
     *
     *         MFN 4             MFN 5             MFN 6            MFN 7
     *   +---------------+-----------------+-----------------+
     *   | offlined page |    head page         tail page    | <- panic's Xen
     *   +---------------+-----------------+-----------------+----------------+
     *                                     |    in-use page      in-use page  |
     *                                     +-----------------+----------------+
     */
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
