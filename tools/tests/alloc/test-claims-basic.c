/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Test basic generic (not node-aware) functionality of memory claims,
 * including installing and redeeming claims, and that claims are
 * respected by allocations and protected against other allocations.
 *
 * Copyright (C) 2026 Cloud Software Group
 */

#define TEST_WRAP_XEN_COMMON_DOMCTL_C /* Enable domctl.c test wrapper */
#include "libtest-page-alloc.h"

/* Install a generic claim set using the direct page_alloc function call */
int test_install_generic_claims_direct(struct domain *d, unsigned long pages)
{
    memory_claim_t claim_set[] = {
        { .target = XEN_DOMCTL_CLAIM_MEMORY_UNPINNED, .pages = pages },
    };

    return domain_set_claim_records(d, ARRAY_SIZE(claim_set), claim_set);
}

/* Install a generic claim set using the domctl helper for the hypercall */
int test_install_generic_claims_domctl(struct domain *d, unsigned long pages)
{
    memory_claim_t claim_set[] = {
        { .target = XEN_DOMCTL_CLAIM_MEMORY_UNPINNED, .pages = pages },
    };
    struct xen_domctl_claim_memory uinfo = {
        .claim_set = { claim_set },
        .nr_entries = ARRAY_SIZE(claim_set),
        .mode = 0,
    };
    bool copyback;

    return claim_memory(d, &uinfo, &copyback);
}

typedef int (*set_global_claims)(struct domain *d, unsigned long pages);
set_global_claims install_generic_claims;

static void test_alloc_domheap_redeems_claims(int start_mfn)
{
    int ret;
    struct page_info *pages = test_pages + start_mfn, *pg;

    test_page_list_add_buddy(pages, order2);
    ASSERT(!install_generic_claims(dom1, 3));
    ASSERT(alloc_domheap_pages(dom1, order1, 0) == pages + 2);
    ASSERT(alloc_domheap_pages(dom1, order0, 0) == pages + 1);
    CHECK(TOTAL_CLAIMS == 0, "Expect all claims consumed after allocations");
    CHECK(FREE_PAGES == 1, "Expect one free page after allocations");

    ASSERT(!install_generic_claims(dom2, FREE_PAGES));

    /* Claim more than dom1 already has fails with ENOMEM (claimed by dom2) */
    ret = install_generic_claims(dom1, domain_tot_pages(dom1) + 1);
    CHECK(ret == -ENOMEM, "dom 1 claim +1 fails due to insufficient pages");

    /* Claim more than dom1's d->max_pages fails with EINVAL */
    ret = install_generic_claims(dom1, dom1->max_pages + 1);
    CHECK(ret == -EINVAL, "dom 1 claim fails due to exceeding max_pages");

    /* Attempt to allocate an order-0 page with a foreign claim present */
    pg = alloc_domheap_pages(dom1, order0, 0);
    CHECK(pg == NULL, "dom 1 allocation fails because of domain 2's claim");
    CHECK(TOTAL_CLAIMS == 1, "Expect domain 2's claim to be still present");
    CHECK(FREE_PAGES == 1, "Expect one free page after failed alloc");
}

/*
 * Test that memory claims are consumed correctly during allocations.
 */
static void test_cancel_claims(int start_mfn)
{
    struct page_info *page = test_pages + start_mfn;
    unsigned long claims;

    /* Create a buddy of order 2 (4 pages) and add it to the heap. */
    test_page_list_add_buddy(page, order2);
    claims = FREE_PAGES / 2;

    /* Claim half of the free pages for dom1 */
    ASSERT(install_generic_claims(dom1, claims) == 0);
    ASSERT(TOTAL_CLAIMS == claims);

    /* Act + Assert 2: Claim all free pages for dom2, should fail */
    ASSERT(install_generic_claims(dom2, FREE_PAGES) == -ENOMEM);
    ASSERT(TOTAL_CLAIMS == claims);

    /* Act + Assert 1: Cancel all claims for dom1 */
    ASSERT(install_generic_claims(dom1, 0) == 0);
    ASSERT(TOTAL_CLAIMS == 0);

    /* Act + Assert 2: Claim all free pages for dom2, should work */
    ASSERT(install_generic_claims(dom2, FREE_PAGES) == 0);
    ASSERT(TOTAL_CLAIMS == FREE_PAGES);
}

int main(int argc, char *argv[])
{
    const char *topic = "Test global claims with old and new interfaces";

    if ( !parse_args(argc, argv, topic) )
        return EXIT_FAILURE;

    install_generic_claims = test_install_generic_claims_domctl;
    init_page_alloc_tests();

    RUN_TESTCASE(TCCL, test_cancel_claims, 4);

    install_generic_claims = test_install_generic_claims_direct;
    RUN_TESTCASE(DCGD, test_alloc_domheap_redeems_claims, 4);

    install_generic_claims = test_install_generic_claims_domctl;
    RUN_TESTCASE(DCGC, test_alloc_domheap_redeems_claims, 4);

    install_generic_claims = xc_domain_claim_memory_unpinned_proxy;
    RUN_TESTCASE(DCGH, test_alloc_domheap_redeems_claims, 4);

    return test_complete();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
