/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Wrapper around xen/common/domctl.c for the allocator test framework.
 *
 * The test framework includes the real domctl.c directly in its translation
 * unit, together with mocks for the Xen types and functions it uses.
 *
 * This file provides the definitions needed for that setup. It also provides
 * proxy functions to call the do_domctl() hypercall handler for test scenarios
 * to install memory claims using the do_domctl(), which is the real consumer
 * of the XEN_DOMCTL_claim_memory command.
 *
 * Copyright (C) 2026 Cloud Software Group
 */
#ifndef TOOLS_TESTS_ALLOC_DOMCTL_PROXY_H
#define TOOLS_TESTS_ALLOC_DOMCTL_PROXY_H

#ifdef TEST_WRAP_XEN_COMMON_DOMCTL_C
#include "domctl-shim.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "../../xen/common/domctl.c"
#pragma GCC diagnostic pop

/*
 * Provide dispatch proxies to call the do_domctl() hypercall handler
 * for test scenarios to install memory claims using the do_domctl(),
 * which is the real consumer of the XEN_DOMCTL_claim_memory command.
 */

/* Harness to call the do_domctl hypercall handler directly */
int xc_domain_claim_memory_harness(uint32_t domid, uint32_t *nr_entries,
                                   memory_claim_t *claim_set, uint32_t mode)
{
    struct xen_domctl_claim_memory uinfo = {
        .claim_set = { claim_set },
        .nr_entries = *nr_entries,
        .mode = mode,
    };
    xen_domctl_t domctl = {
        .interface_version = XEN_DOMCTL_INTERFACE_VERSION,
        .cmd = XEN_DOMCTL_claim_memory,
        .domain = domid,
        .u.claim_memory = uinfo,
    };
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) handle;

    set_xen_guest_handle(handle, &domctl);
    int ret = do_domctl(handle);
    if ( !ret )
        *nr_entries = handle.p->u.claim_memory.nr_entries;
    return ret;
}

int xc_domain_claim_memory_proxy(struct domain *d, uint32_t nr,
                                 memory_claim_t *claim_set)
{
    return xc_domain_claim_memory_harness(d->domain_id, &nr, claim_set, 0);
}

/* Install a host-wide claim set using the do_domctl hypercall handler */
int xc_domain_claim_memory_host_proxy(struct domain *d, unsigned long pages)
{
    memory_claim_t claim_set[] = {
        { .target = XEN_DOMCTL_CLAIM_MEMORY_HOST, .pages = pages },
    };

    return xc_domain_claim_memory_proxy(d, ARRAY_SIZE(claim_set), claim_set);
}

int xc_domain_get_memory_claims_proxy(struct domain *d, uint32_t *nr,
                                      memory_claim_t *claim_set)
{
    return xc_domain_claim_memory_harness(d->domain_id, nr, claim_set,
                                          XEN_DOMCTL_CLAIM_MEMORY_GET);
}

int assert_claims_via_domctl(struct domain *d, uint32_t expected_records,
                             memory_claim_t *expected_claims)
{
    uint32_t records = expected_records;
    memory_claim_t claim_set[expected_records];
    int ret = xc_domain_get_memory_claims_proxy(d, &records, claim_set);

    CHECK(ret == 0, "xc_domain_get_memory_claims_proxy succeeds");
    CHECK(records == expected_records, "Expect %u claim records returned",
          expected_records);

    for ( uint32_t i = 0; i < expected_records; i++ )
        CHECK(claim_set[i].pages == expected_claims[i].pages &&
              claim_set[i].target == expected_claims[i].target,
              "Expect claim record %x to have target %u and pages %" PRIu64,
              i, expected_claims[i].target, expected_claims[i].pages);
    return ret;
}

#define CLAIMS(d, claim_set) assert_claims_via_domctl(d, ARRAY_SIZE(claim_set), \
                                                      claim_set)

#endif /* TEST_WRAP_XEN_COMMON_DOMCTL_C */

#endif
