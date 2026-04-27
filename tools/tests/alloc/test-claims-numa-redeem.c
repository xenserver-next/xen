/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Integration tests for redeeming NUMA memory claim set as implemented
 * in xen/common/page_alloc.c's redeem_claims_for_allocation() and
 * related functions.
 *
 * redeem_claims_for_allocation() is exercised indirectly through
 * alloc_domheap_pages() which is the primary interface for allocating
 * pages from a domain's heap.
 *
 * By means of domain_install_claim_set(), a claim set with generic and
 * per-NUMA-node claims is installed for a dummy domain, and then
 * allocations with NUMA node affinity are performed to verify that the
 * appropriate claims are redeemed (same-node first, generic fallback next,
 * then other nodes to not exceed page limits). The test also verifies that
 * aggregate counters are updated correctly after each allocation.
 *
 * The test verifies that when a domain has a claim set installed with
 * generic and per-NUMA-node claims, allocations that specify NUMA node
 * affinity will redeem the appropriate claims (same-node first, generic
 * fallback claim next, then other nodes to not exceed page limits).
 * It also verifies that the aggregate claim counters are updated
 * correctly after each allocation.
 *
 * Copyright (C) 2026 Cloud Software Group
 */

#define CONFIG_NUMA 1 /* Enable NUMA support in the test environment.*/
#define TEST_WRAP_XEN_COMMON_DOMCTL_C /* Enable domctl.c test wrapper */
#include "libtest-page-alloc.h"

typedef int (*set_numa_claims)(struct domain *d, uint32_t nr_claims,
                               memory_claim_t *claim_set);
set_numa_claims install_numa_claims;

/*
 * Test redeeming NUMA memory claims in exchange for allocations,
 * and the redeemed claims are correctly reflected in the domain's
 * claim state and the aggregate claim counters.
 */
static void test_claims_numa_install(int start_mfn)
{
    int zone, ret;
    uint32_t records;
    struct page_info *pages = test_pages + start_mfn, *allocated;

    /*
     * PREPARE
     */

    /*
     * Node 1's pages start at the pfn set by init_numa_node_data():
     * node_data[node1].node_start_pfn = start_mfn + 8 (8 MFNs per node with
     * memnode_shift=3). The order-2 buddy (4 pages) placed there satisfies
     * the 2-page node1 claim and provides enough total pages for the
     * 2 generic + 2 node0 + 2 node1 = 6-page claim set (2 + 4 = 6 total).
     */
    struct page_info *pages_node1 =
        test_pages + node_data[node1].node_start_pfn;

    /* Create an order-1 buddy (2 pages) for node 0 and add it to the heap. */
    zone = test_page_list_add_buddy(pages, order1);

    /* Create an order-2 buddy (4 pages) for node 1 and add it to the heap. */
    test_page_list_add_buddy(pages_node1, order2);

    /* Install a claim set with generic + per-NUMA-node claims. */
    memory_claim_t claim_set[] = {
        { .target = XEN_DOMCTL_CLAIM_MEMORY_UNPINNED, .pages = 2 },
        { .target = node0,                            .pages = 2 },
        { .target = node1,                            .pages = 2 },
    };
    records = ARRAY_SIZE(claim_set);
    ret = install_numa_claims(dom1, records, claim_set);
    CHECK(ret == 0, "domain_install_claim_set should succeed: %d", ret);

    /* Assert dom1's claims */
    CHECK(TOTAL_CLAIMS == 6, "Expect 6 total claims after installation");
    CHECK(DOM_GENERIC_CLAIMS(dom1) == 2,
          "Expect dom1 having 2 generic claims after installation");
    CHECK(DOM_NODE_CLAIMS(dom1, node0) == 2,
          "Expect dom1 having 2 claims for node0 after installation");
    CHECK(DOM_NODE_CLAIMS(dom1, node1) == 2,
          "Expect dom1 having 2 claims for node1 after installation");

    /* Allocate an order-0 page from node 0 for the dummy domain. */
    allocated = alloc_domheap_pages(dom1, order0, MEMF_node(node0));
    CHECK(allocated != NULL, "alloc_domheap_pages should succeed");

    /* Verify the state of the aggregate counters after allocation. */
    CHECK(TOTAL_CLAIMS == 5, "Expect 5 total claims left after allocation");
    CHECK(FREE_PAGES == 5, "Expect 5 free pages left after allocation");

    /* Assert dom1's claims after the allocation from node0 */
    CHECK(DOM_GENERIC_CLAIMS(dom1) == 2,
          "Expect dom1 still having 2 generic claims after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node0) == 1,
          "Expect dom1 having 1 claim for node0 after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node1) == 2,
          "Expect dom1 still having 2 claims for node1 after allocation");

    ret = xc_domain_get_memory_claims_proxy(dom1, &records, claim_set);
    CHECK(ret == 0, "xc_domain_get_memory_claims_proxy succeeds: %d", ret);
    CHECK(records == 3, "Expect 3 claim records returned");
    CHECK(claim_set[0].pages == 2 &&
          claim_set[0].target == XEN_DOMCTL_CLAIM_MEMORY_UNPINNED,
          "Expect claim record 0 to have total claim of 5 after allocation");
    CHECK(claim_set[1].pages == 1 && claim_set[1].target == node0,
          "Expect claim record 1 to have node0 claim of 1 after allocation");
    CHECK(claim_set[2].pages == 2 && claim_set[2].target == node1,
          "Expect claim record 2 to have node1 claim of 2 after allocation");

    /* Allocate an order-0 page from node 1 for the dummy domain. */
    allocated = alloc_domheap_pages(dom1, order0, MEMF_node(node1));
    CHECK(allocated != NULL, "order-0 alloc from node1");

    /* Assert dom1's claims after the allocation from node1 */
    CHECK(DOM_GENERIC_CLAIMS(dom1) == 2,
          "Expect dom1 still having 2 generic claims after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node0) == 1,
          "Expect dom1 having 1 claim for node0 after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node1) == 1,
          "Expect dom1 having 1 claim for node1 after allocation");

    ret = xc_domain_get_memory_claims_proxy(dom1, &records, claim_set);
    CHECK(ret == 0, "xc_domain_get_memory_claims_proxy succeeds: %d", ret);
    CHECK(records == 3, "Expect 3 claim records returned");
    CHECK(claim_set[0].pages == 2 &&
          claim_set[0].target == XEN_DOMCTL_CLAIM_MEMORY_UNPINNED,
          "Expect claim record 0 to have total claim of 4 after allocation");
    CHECK(claim_set[1].pages == 1 && claim_set[1].target == node0,
          "Expect claim record 1 to have node0 claim of 1 after allocation");
    CHECK(claim_set[2].pages == 1 && claim_set[2].target == node1,
          "Expect claim record 2 to have node1 claim of 1 after allocation");

    /* Allocate an order-1 page from node 1 for the dummy domain. */
    allocated = alloc_domheap_pages(dom1, order1, MEMF_node(node1));
    CHECK(allocated != NULL, "order-1 alloc from node1");

    /* Assert dom1's claims after the allocation from node1 */
    CHECK(DOM_GENERIC_CLAIMS(dom1) == 1,
          "Expect dom1 having redeemed one generic claim after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node0) == 1,
          "Expect dom1 having 1 claim for node0 after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node1) == 0,
          "Expect dom1 having 0 claims for node1 after allocation");

    ret = xc_domain_get_memory_claims_proxy(dom1, &records,
                                            claim_set);
    CHECK(ret == 0, "xc_domain_get_memory_claims_proxy succeeds: %d", ret);
    CHECK(records == 2, "Expect 2 claim records returned");
    CHECK(claim_set[0].pages == 1 &&
          claim_set[0].target == XEN_DOMCTL_CLAIM_MEMORY_UNPINNED,
          "Expect claim record total to have total claim of 2 after allocation");
    CHECK(claim_set[1].pages == 1 && claim_set[1].target == node0,
          "Expect claim record 1 to have node0 claim of 1 after allocation");

    /* Allocate the last order-0 claim from node 1 */
    allocated = alloc_domheap_pages(dom1, order0, MEMF_node(node1));
    CHECK(allocated != NULL, "order-0 alloc from node1");

    /* Assert dom1's claims after the allocation from node1 */
    CHECK(DOM_GENERIC_CLAIMS(dom1) == 0,
          "Expect dom1 having redeemed all generic claims after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node0) == 1,
          "Expect dom1 having 1 claim for node0 after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node1) == 0,
          "Expect dom1 having 0 claims for node1 after allocation");

    ret = xc_domain_get_memory_claims_proxy(dom1, &records,
                                            claim_set);
    CHECK(ret == 0, "xc_domain_get_memory_claims_proxy succeeds");
    CHECK(records == 2, "Expect 2 claim records returned");
    CHECK(claim_set[0].pages == 0 &&
          claim_set[0].target == XEN_DOMCTL_CLAIM_MEMORY_UNPINNED,
          "Expect claim record 0 to have total claim of 2 after allocation");
    CHECK(claim_set[1].pages == 1 && claim_set[1].target == node0,
          "Expect claim record 1 to have node0 claim of 1 after allocation");

    /* Allocate an order-0 page from node 1 for the dummy domain. */
    allocated = alloc_domheap_pages(dom1, order0, MEMF_node(node1));
    CHECK(allocated != NULL, "order-0 alloc from node1");

    /* Assert dom1's claims after the allocation from node1 */
    CHECK(DOM_GENERIC_CLAIMS(dom1) == 0,
          "Expect dom1 having redeemed all generic claims after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node0) == 0,
          "Expect dom1 having 0 claims for node0 after allocation");
    CHECK(DOM_NODE_CLAIMS(dom1, node1) == 0,
          "Expect dom1 having 0 claims for node1 after allocation");

    ret = xc_domain_get_memory_claims_proxy(dom1, &records,
                                            claim_set);
    CHECK(ret == 0, "xc_domain_get_memory_claims_proxy succeeds: %d", ret);
    CHECK(records == 1,
          "Expect 1 claim records returned by get_memory_claims_proxy");
    CHECK(claim_set[0].pages == 0 &&
          claim_set[0].target == XEN_DOMCTL_CLAIM_MEMORY_UNPINNED,
          "Expect claim record 0 to have total claim of 2 after allocation");
}

int main(int argc, char *argv[])
{
    const char *topic = "Test legacy claims with allocation from the heap";

    if ( !parse_args(argc, argv, topic) )
        return EXIT_FAILURE;

    init_page_alloc_tests();

    /* Run test cases with different NUMA claim installation methods */

    /* Run the test with a direct call to domain_set_claim_records() */
    install_numa_claims = domain_set_claim_records;
    RUN_TESTCASE(CNIS, test_claims_numa_install, 0);

    /* Run the test using xc_domain_claim_memory_proxy() (uses do_domctl) */
    install_numa_claims = xc_domain_claim_memory_proxy;
    RUN_TESTCASE(CNIH, test_claims_numa_install, 0);

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
