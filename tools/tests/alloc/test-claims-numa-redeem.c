/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Integration tests for redeeming NUMA memory claims.
 *
 * The test verifies that when a domain has a claim set installed with
 * host-wide and per-NUMA-node claims, allocations that specify NUMA node
 * affinity will redeem the appropriate claims (same-node first, host-wide
 * fallback claim next, then other nodes, to not exceed page limits).
 * It also verifies that the aggregate claim counters are updated
 * correctly after each allocation.
 *
 * Copyright (C) 2026 Cloud Software Group
 */

#define CONFIG_NUMA 1 /* Enable NUMA support in the test environment.*/
#define TEST_WRAP_XEN_COMMON_DOMCTL_C /* Enable domctl.c test wrapper */
#include "libtest-page-alloc.h"

typedef int (*set_numa_claims)
    (struct domain *d, uint32_t nr_claims,  memory_claim_t *claim_set);
set_numa_claims install_numa_claims;

/*
 * Test redeeming NUMA memory claims in exchange for allocations,
 * and the redeemed claims are correctly reflected in the domain's
 * claim state and the aggregate claim counters.
 */
static void test_claims_numa_install(int start_mfn)
{
    test_page_list_add_node_buddy(node0, start_mfn, order2);
    test_page_list_add_node_buddy(node1, start_mfn, order2);

    /* Install a claim set with host-wide + per-NUMA-node claims. */
    memory_claim_t claim_set[] = {
        { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = 2 },
        { .target = node0,                            .pages = 2 },
        { .target = node1,                            .pages = 2 },
    };
    ASSERT(!install_numa_claims(dom1, ARRAY_SIZE(claim_set), claim_set));
    CHECK(TOTAL_CLAIMS == 6, "Expect 6 total claims after installation");
    CLAIMS(dom1,
           ((memory_claim_t[]){
                { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = 2 },
                { .target = node0, .pages = 2 },
                { .target = node1, .pages = 2 }
            }));

    ASSERT(alloc_domheap_pages(dom1, order0, MEMF_node(node0)));
    CHECK(TOTAL_CLAIMS == 5, "Expect 5 total claims left after allocation");
    CHECK(FREE_PAGES == 7, "Expect 7 free pages left after allocation");
    CLAIMS(dom1,
           ((memory_claim_t[]){
                { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = 2 },
                { .target = node0, .pages = 1 },
                { .target = node1, .pages = 2 }
            }));

    /* An allocation node 1 redeems the a claim from node 1 */
    ASSERT(alloc_domheap_pages(dom1, order0, MEMF_node(node1)));
    CHECK(TOTAL_CLAIMS == 4, "Expect 4 total claims left after allocation");
    CHECK(FREE_PAGES == 6, "Expect 6 free pages left after allocation");
    CLAIMS(dom1,
           ((memory_claim_t[]){
                { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = 2 },
                { .target = node0, .pages = 1 },
                { .target = node1, .pages = 1 }
            }));

    /* An allocation node 1 redeems the last claim from node 1 */
    ASSERT(alloc_domheap_pages(dom1, order1, MEMF_node(node1)));
    CHECK(TOTAL_CLAIMS == 2, "Expect 2 total claims left after allocation");
    CHECK(FREE_PAGES == 4, "Expect 4 free pages left after allocation");
    CLAIMS(dom1,
           ((memory_claim_t[]){
                { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = 1 },
                { .target = node0, .pages = 1 },
            }));

    /* An allocation node 1 falls back to redeem from the host-wide claim */
    ASSERT(alloc_domheap_pages(dom1, order0, MEMF_node(node1)));
    CHECK(TOTAL_CLAIMS == 1, "Expect 1 total claims left after allocation");
    CHECK(FREE_PAGES == 3, "Expect 3 free pages left after allocation");
    CLAIMS(dom1,
           ((memory_claim_t[]){
                { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = 0 },
                { .target = node0, .pages = 1 },
            }));

    /* An allocation node 1 falls back to redeem from node 0 */
    ASSERT(alloc_domheap_pages(dom1, order0, MEMF_node(node1)));
    CHECK(TOTAL_CLAIMS == 0, "Expect 0 total claims left after allocation");
    CHECK(FREE_PAGES == 2, "Expect 2 free pages left after allocation");
    CLAIMS(dom1,
           ((memory_claim_t[]){
                { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = 0 },
            }));
}

int main(int argc, char *argv[])
{
    const char *topic = "Test legacy claims with allocation from the heap";

    if ( !parse_args(argc, argv, topic) )
        return EXIT_FAILURE;

    init_page_alloc_tests();

    /* Run test cases with different NUMA claim installation methods */

    /* Run the test with a direct call to domain_set_claim_entries() */
    install_numa_claims = domain_set_claim_entries;
    RUN_TESTCASE(CNIS, test_claims_numa_install, 4);

    /* Run the test using xc_domain_claim_memory_proxy() (uses do_domctl) */
    install_numa_claims = xc_domain_claim_memory_proxy;
    RUN_TESTCASE(CNIH, test_claims_numa_install, 4);

    return test_complete();
}
