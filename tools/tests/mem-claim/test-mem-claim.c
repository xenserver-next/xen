/* SPDX-License-Identifier: GPL-2.0-only */
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xenforeignmemory.h>
#include <xengnttab.h>
#include <xen-tools/common-macros.h>

static unsigned int nr_failures;
#define fail(fmt, ...)                          \
({                                              \
    nr_failures++;                              \
    (void)printf(fmt, ##__VA_ARGS__);           \
})

#define MB_PAGES(x) (MB(x) / XC_PAGE_SIZE)

#define CLAIM_TEST_ORDER 9 /* 2M */

static xc_interface *xch;
static uint32_t domid = DOMID_INVALID;

static xc_physinfo_t physinfo;
static unsigned int claim_test_node;

static struct xen_domctl_createdomain create = {
    .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
    .max_vcpus = 1,
    .max_grant_frames = 1,
    .grant_opts = XEN_DOMCTL_GRANT_version(1),

    .arch = {
#if defined(__x86_64__) || defined(__i386__)
        .emulation_flags = XEN_X86_EMU_LAPIC,
#endif
    },
};

typedef int (*claim_fn_t)(xc_interface *xch, uint32_t domid,
                          unsigned long pages);

/* Wrapper function to test claiming memory using xc_domain_claim_pages. */
static int wrap_claim_pages(xc_interface *xch,
                            uint32_t domid,
                            unsigned long pages)
{
    return xc_domain_claim_pages(xch, domid, pages);
}

/* Wrapper function to test claiming memory using xc_domain_claim_memory. */
static int wrap_claim_memory(xc_interface *xch,
                             uint32_t domid,
                             unsigned long pages)
{
    memory_claim_t claim[] = {
        XEN_NODE_CLAIM_INIT(pages, XEN_DOMCTL_CLAIM_MEMORY_NO_NODE)
    };

    int rc = xc_domain_claim_memory(xch, domid, 0, NULL);
    if ( rc != -1 || errno != EINVAL )
    {
        fail("Expected nr_claims == 0 to fail with EINVAL\n");
        return rc;
    }

    return xc_domain_claim_memory(xch, domid, 1, claim);
}

/* Wrapper to test claiming memory using xc_domain_claim_memory on a NUMA node */
static int wrap_claim_memory_node(xc_interface *xch,
                                  uint32_t domid,
                                  unsigned long pages)
{
    int rc;
    memory_claim_t claims[UINT8_MAX + 1] = {}; /* + 1 to test overflow check */

    /* claim with a node that is not present */
    claims[0] = (memory_claim_t)XEN_NODE_CLAIM_INIT(pages, physinfo.nr_nodes);

    /* Check the return value of claiming memory on an invalid node */
    rc = xc_domain_claim_memory(xch, domid, 1, claims);
    if ( rc != -1 || errno != ENOENT )
    {
        fail("Expected claim failure on invalid node to fail with ENOENT\n");
        return rc;
    }
    /*
     * Check the return value of claiming on two nodes (not yet implemented)
     * and that the valid claim is rejected when nr_claims > 1. We expect that
     * the API will reject the call due exceeding nr_claims before it checks
     * the validity of the node(s), so we expect EINVAL rather than ENOENT.
     */
    rc = xc_domain_claim_memory(xch, domid, 2, claims);
    if ( rc != -1 || errno != EINVAL )
    {
        fail("Expected nr_claims == 2 to fail with EINVAL (for now)\n");
        return rc;

    }
    /* Likewise check with nr_claims > MAX_UINT8 to test overflow */
    rc = xc_domain_claim_memory(xch, domid, UINT8_MAX + 1, claims);
    if ( rc != -1 || errno != EINVAL )
    {
        fail("Expected nr_claims = UINT8_MAX + 1 to fail with EINVAL\n");
        return rc;
    }
    /* Likewise check with a node of MAX_UINT8 + 1 to test overflow */
    claims[0].node = UINT8_MAX + 1;
    rc = xc_domain_claim_memory(xch, domid, 1, claims);
    if ( rc != -1 || errno != ENOENT )
    {
        fail("Expected node == UINT8_MAX + 1 to fail with ENOENT\n");
        return rc;
    }
    /* Test with pages exceeding INT32_MAX to check overflow */
    claims[0] = (memory_claim_t)XEN_NODE_CLAIM_INIT((unsigned)INT32_MAX + 1, 0);
    rc = xc_domain_claim_memory(xch, domid, 1, claims);
    if ( rc != -1 || errno != ENOMEM )
    {
        fail("Expected ENOMEM with pages > INT32_MAX\n");
        return rc;
    }
    /* Test with pad not set to zero */
    claims[0] = (memory_claim_t)XEN_NODE_CLAIM_INIT(pages, claim_test_node);
    claims[0].pad = 1;
    rc = xc_domain_claim_memory(xch, domid, 1, claims);
    if ( rc != -1 || errno != EINVAL )
    {
        fail("Expected EINVAL with pad not set to zero\n");
        return rc;
    }

    /* Pass a valid claim for the selected node and continue the test */
    claims[0] = (memory_claim_t)XEN_NODE_CLAIM_INIT(pages, claim_test_node);
    return xc_domain_claim_memory(xch, domid, 1, claims);
}

static int get_node_free_pages(unsigned int node, unsigned long *free_pages)
{
    int rc;
    unsigned int num_nodes = 0;
    xc_meminfo_t *meminfo;

    rc = xc_numainfo(xch, &num_nodes, NULL, NULL);
    if ( rc )
        return rc;

    if ( node >= num_nodes )
    {
        errno = EINVAL;
        return -1;
    }

    meminfo = calloc(num_nodes, sizeof(*meminfo));
    if ( !meminfo )
        return -1;

    rc = xc_numainfo(xch, &num_nodes, meminfo, NULL);
    if ( rc )
        goto out;

    *free_pages = meminfo[node].memfree / XC_PAGE_SIZE;

 out:
    free(meminfo);
    return rc;
}

static void run_test(claim_fn_t claim_call_wrapper, const char *claim_name,
                     bool host_wide_claim)
{
    int rc;
    uint64_t free_heap_bytes;
    unsigned long free_pages, claim_pages;
    const unsigned long request_pages = 1UL << CLAIM_TEST_ORDER;

    printf("  Testing %s\n", claim_name);
    /*
     * Check that the system is quiescent.  Outstanding claims is a global
     * field.
     */
    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    printf("Free pages: %"PRIu64", Outstanding claims: %"PRIu64"\n",
           physinfo.free_pages, physinfo.outstanding_pages);

    if ( physinfo.outstanding_pages )
        return fail("  Test needs running on a quiescent system\n");

    /*
     * We want any arbitrary domain.  Start with HVM/HAP, falling back to
     * HVM/Shadow and then to PV.  The dom0 running this test case is one of
     * these modes.
     */
#if defined(__x86_64__) || defined(__i386__)
    if ( !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_hap) )
        create.flags &= ~XEN_DOMCTL_CDF_hap;

    if ( !(physinfo.capabilities & (XEN_SYSCTL_PHYSCAP_hap|XEN_SYSCTL_PHYSCAP_shadow)) ||
         !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_hvm) )
    {
        create.flags &= ~XEN_DOMCTL_CDF_hvm;
        create.arch.emulation_flags = 0;
    }
#endif

    rc = xc_domain_create(xch, &domid, &create);
    if ( rc )
        return fail("  Domain create failure: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_domain_setmaxmem(xch, domid, -1);
    if ( rc )
        return fail("  Failed to set maxmem: %d - %s\n",
                    errno, strerror(errno));

    printf("  Created d%u\n", domid);

    /*
     * Creating a domain shouldn't change the claim.  Check it's still 0.
     */
    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages )
        return fail("  Unexpected outstanding claim of %"PRIu64" pages\n",
                    physinfo.outstanding_pages);

    rc = xc_availheap(xch, 0, 0, host_wide_claim ? -1 : (int)claim_test_node,
                      &free_heap_bytes);
    if ( rc )
        return fail("  Failed to query available heap: %d - %s\n",
                    errno, strerror(errno));

    free_pages = free_heap_bytes / XC_PAGE_SIZE;
    if ( !host_wide_claim )
    {
        rc = get_node_free_pages(claim_test_node, &free_pages);
        if ( rc )
            return fail("  Failed to query free pages on node %u: %d - %s\n",
                        claim_test_node, errno, strerror(errno));
    }

    if ( free_pages <= request_pages + 1 )
        return fail("  Not enough free pages (%lu) to test %s claim enforcement\n",
                    free_pages, host_wide_claim ? "host-wide" : "node");

    claim_pages = free_pages - request_pages + 1;

    rc = claim_call_wrapper(xch, domid, claim_pages);
    if ( rc )
        return fail("  Failed to claim calculated RAM amount: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages != claim_pages )
        return fail("  Expected claim to be %lu pages, got %"PRIu64" pages\n",
                    claim_pages, physinfo.outstanding_pages);

    {
        uint32_t other_domid = DOMID_INVALID;
        xen_pfn_t other_ram[] = { 0 };
        unsigned int memflags = host_wide_claim ? 0 : XENMEMF_exact_node(claim_test_node);

        rc = xc_domain_create(xch, &other_domid, &create);
        if ( rc )
            return fail("  Second domain create failure: %d - %s\n",
                        errno, strerror(errno));

        rc = xc_domain_setmaxmem(xch, other_domid, -1);
        if ( rc )
        {
            fail("  Failed to set maxmem for second domain: %d - %s\n",
                 errno, strerror(errno));
            goto destroy_other;
        }

        rc = xc_domain_populate_physmap_exact(
            xch, other_domid, ARRAY_SIZE(other_ram), CLAIM_TEST_ORDER,
            memflags, other_ram);
        if ( rc == 0 )
            fail("  Expected %s claim to block second-domain allocation\n",
                 host_wide_claim ? "host-wide" : "node");

 destroy_other:
        rc = xc_domain_destroy(xch, other_domid);
        if ( rc )
            return fail("  Failed to destroy second domain: %d - %s\n",
                        errno, strerror(errno));
    }

    /*
     * Allocate one CLAIM_TEST_ORDER chunk to the domain. This should reduce
     * the outstanding claim by request_pages. For node claims, request memory
     * from the claimed node.
     */
    xen_pfn_t ram[] = { 0 };
    rc = xc_domain_populate_physmap_exact(
        xch, domid, ARRAY_SIZE(ram), CLAIM_TEST_ORDER,
        host_wide_claim ? 0 : XENMEMF_node(claim_test_node), ram);
    if ( rc )
        return fail("  Failed to populate physmap domain: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages != claim_pages - request_pages )
        return fail("  Expected claim to be %lu pages, got %"PRIu64" pages\n",
                    claim_pages - request_pages, physinfo.outstanding_pages);

    /*
     * Destroying the domain should release the outstanding 2M claim.
     */
    rc = xc_domain_destroy(xch, domid);

    /* Cancel the cleanup path, even in the case of an error. */
    domid = DOMID_INVALID;

    if ( rc )
        return fail("  Failed to destroy domain: %d - %s\n",
                    errno, strerror(errno));

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("  Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    if ( physinfo.outstanding_pages )
        return fail("  Expected no outstanding claim, got %"PRIu64" pages\n",
                    physinfo.outstanding_pages);
}

int main(int argc, char **argv)
{
    int rc;
    unsigned int num_nodes = 0;
    xc_meminfo_t *meminfo = NULL;

    printf("Memory claims tests\n");

    xch = xc_interface_open(NULL, NULL, 0);

    if ( !xch )
        err(1, "xc_interface_open");

    rc = xc_numainfo(xch, &num_nodes, NULL, NULL);
    if ( rc || !num_nodes )
        err(1, "xc_numainfo");

    meminfo = calloc(num_nodes, sizeof(*meminfo));
    if ( !meminfo )
        err(1, "calloc");

    rc = xc_numainfo(xch, &num_nodes, meminfo, NULL);
    if ( rc )
        err(1, "xc_numainfo");

    claim_test_node = 0;
    for ( unsigned int i = 1; i < num_nodes; i++ )
    {
        if ( meminfo[i].memfree > meminfo[claim_test_node].memfree )
            claim_test_node = i;
    }

    free(meminfo);

    struct {
        claim_fn_t fn;
        const char *name;
        bool host_wide;
    } tests[] = {
        {
            .fn = wrap_claim_pages,
            .name = "xc_domain_claim_pages",
            .host_wide = true,
        },
        {
            .fn = wrap_claim_memory,
            .name = "xc_domain_claim_memory",
            .host_wide = true,
        },
        {
            .fn = wrap_claim_memory_node,
            .name = "xc_domain_claim_memory_node",
            .host_wide = false,
        },
    };
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);
    for ( size_t i = 0; i < num_tests; i++ )
    {
        run_test(tests[i].fn, tests[i].name, tests[i].host_wide);
        if ( domid != DOMID_INVALID )
        {
            rc = xc_domain_destroy(xch, domid);
            if ( rc )
                fail("  Failed to destroy domain: %d - %s\n",
                     errno, strerror(errno));
            domid = DOMID_INVALID;
        }
    }

    return !!nr_failures;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
