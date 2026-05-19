/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Verify if offlining a predecessor of pages which must not be merged
 * into an unaligned buddy is handled correctly. It verifies the Xen
 * page allocator does not merge such unaligned buddies back to the
 * free list, which would cause a chain of events leading to a crash
 * of a running Xen instance after a few allocations and frees.
 *
 * The test case verifies if this chain of events occurs in an isolated
 * scenario by offlining a page with an even MFN which has more than two
 * tail pages following it.
 *
 * If in case this returns an unaligned buddy to the free list, a few
 * allocations and a free later, the corrupted free list state causes
 * a future allocation to hit a BUG() and crash the instance. The test case
 * verifies the free list behavior and unless fixed, the resulting crash.
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

    if (expect_free_list_corruption)
        EXPECT_FAIL_BEGIN();
    CHECK(page->list.next && page->list.prev, "The free list is corrupt now!");
    if (expect_free_list_corruption)
        EXPECT_FAIL_END(1);

    if (page->list.next && page->list.prev)
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

    /* Prepare */
    test_page_list_add_buddy(pg, order2); /* Seed the heap with a buddy */

    /* Act */
    offline_page(page_to_mfn(pg), 0, &status);
    CHECK(status & PG_OFFLINE_OFFLINED, "Page should be offlined");

    /* Assert */
    EXPECT_FAIL_BEGIN();
    CHECK(page_aligned(pg + 1), "The buddy #%lu is not aligned to order-%d",
                                mfn_x(page_to_mfn(pg + 1)), PFN_ORDER(pg + 1));
    EXPECT_FAIL_END(1);

    /* Allocate and free a page to trigger buddy merging on free. */
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
     */
    alloc_domheap_pages(dom1, order0, 0); /* Triggers BUG() */
}

int main(int argc, char *argv[])
{
    const char *topic = "Test not merging unaligned buddies onto the free list";

    if (!parse_args(argc, argv, topic))
        return EXIT_FAILURE;

    init_page_alloc_tests();
    RUN_TESTCASE("TUBM", test_unaligned_buddy_merge, 4);

    return test_complete();
}

