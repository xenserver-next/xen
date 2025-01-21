# NUMA-aware memory allocation in X86 meminit_hvm()

`meminit_hvm()` is registered as the `meminit` hook for HVM domains.
This hook is called by `xc_dom_boot_mem_init()` which is used by
to setup, claim, and allocate the HVM domain's memory.

##  `xc_dom_boot_mem_init()`

In all cases, `xc_dom_boot_mem_init()` is called:

https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_boot.c#L110

Except error handling and tracing, all it does is to call the
architecture-specific `meminit` hook for the domain type:

```c
rc = dom->arch_hooks->meminit(dom);
```

This calls the [meminit_hvm()](meminit_hvm.md) libxc function.

## `meminit_hvm()`, the x86 HVM meminit() hook

For an x86 HVM domain, the meminit hook called by  `xc_dom_boot_mem_init()`
is the libxc function `meminit_hvm()`:
https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_x86.c#L1348

This libxenguest file is (among related things) also responsible to:
- prepare page tables
- fill architecture-specific structs

### Optionally claiming a memory reservation

if `dom->claim_enabled` is set by the caller,
`meminit_pv` and `meminit_hvm` call the xenctrl
function `xc_domain_claim_pages()`:

https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_x86.c#L1348

It calls the hypercall `xc_memory_op(xch, XENMEM_claim_pages, &reservation)`

https://github.com/xen-project/xen/blob/master/tools/libs/ctrl/xc_domain.c#L1078

The purpose of XENMEM_claim_pages is:
> Attempt to stake a claim for a domain on a quantity of pages
> of system RAM, but _not_ assign specific pageframes. Only
> arithmetic is performed so the hypercall is very fast and need
> not be preemptible, thus sidestepping time-of-check-time-of-use
> races for memory allocation. Returns 0 if the hypervisor page
> allocator has atomically and successfully claimed the requested
> number of pages, else non-zero.
>
> Any domain may have only one active claim. When sufficient memory
> has been allocated to resolve the claim, the claim silently expires.
> Claiming zero pages effectively resets any outstanding claim
> and is always successful.

Note: As explained, each domain can only have one reservation.
Thus, reservations do not have or need any identifier   .

It is set up as:
```c
struct xen_memory_reservation reservation = {
    .nr_extents   = nr_pages, /* number of pages to claim */
    .extent_order = 0, /* an order 0 means: 4k pages */
    .mem_flags    = 0, /* no flags */
    .domid        = domid /* for the new domain */
};
```

As a note: Other hypercalls use flags like `mem_flags`
to pass information like `strict` (in Xen: `exact`)
(fail if not everyting cloud be claimed) and NUMA nodes.

However, as long as there can only be one claim per domain,
this mechanism is not capable to support NUMA yet, as the
claim would have to support multiple reservations:
One for each NUMA node.

One component of the NUMA improvements would be to check if we
can use flag bits in `mem_flags` for a single NUMA node and
to fail if not all pages could be claimed on the specified node.

For full NUMA support, especially full vNUMA support,
we need a claim_pages_numa hypercall that accels multiple
reservations to claim per domain (one for each NUMA node).

### Populate-On-Demand (POD)

If `dom->target_pages` is smaller than `dom->total_pages`,
the X86 `meminit_hvm()` function enables `XENMEMF_populate_on_demand`:

https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_x86.c#L1368

In this case, after the optionally claiming of a memory reservation for the amount of `dom->target_pages`,
`meminit_hvm()` function calls `xc_domain_set_pod_target()`
to set the populate on demand target to `dom->target_pages`.

https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_x86.c#L1454

### vmemranges

The allocation of domain boot memory set up using vmemranges.
`meminit_hvm()` creates a default `vmemranges` array based on
the amount of lowmem (below 4G, until `dom->lowmem_end`) and
highmem (above 4G) until `dom->highmem_end`.

The default vmemranges do not carry information about from
which NUMA node the memory shall shall be allocated.

The x86 `meminit_hvm()` uses two vmemranges as fallback:
- `0` to `dom->lowmem_end`
- `4G` to `dom->highmem_end`
- The NUMA node IDs (`nid`) are set to 0.
- A dummy `vnode_to_pnode[]` for `nid` maps `0` to `XC_NUMA_NO_NODE`.

Code:
https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_x86.c#L1371

Alternatively, callers of the meminit hook have the possibilty
pass an array of memory ranges in `dom->vmemranges`, which can
contain a specific NUMA node for each vmemrange:

While the vmemranges have been added for vNUMA, `meminit_hvm()` does
not care about vNUMA, NUMA or no NUMA at all. It is only concerned about memory init.
Hence, its code always acts on `vmemranges`, to avoid code duplications
and creates default non-NUMA `vmemranges` if the caller does not pass
specific `dom->vmemranges` for NUMA cases.

Caveat: When passing `dom->vmemranges`,
Populate-On-Demand (`target_pages` < `total_pages`) cannot be used,
with custom `vmemranges` as Populate-On-Demand does not support
passing NUMA nodes, which is part of vmemranges for vNUMA.

This means, a vNUMA domain or a domain with boot memory allocation
from a specific NUMA node cannot be configured to be also using Populate-On-Demand.
A a result, memory overcommitment with ballooning is currently not possible for those.

### Memory allocation of the Domain's memory

`meminit_hvm()` attempts to allocate 1GB pages if possible,
fall back on 2MB pages if 1GB allocation fails
and 4KB pages will be used eventually if both fail:

https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_x86.c#L1475

Partial superpage extents are clipped to superpage
boundaries to allow the use of superpages as far as
possible.

For each `vmemrange`, `new_memflags` are composed, based
on the base `memflags`:

```c
unsigned int new_memflags = memflags;
unsigned int vnode = vmemranges[vmemid].nid;
// With custom vmemranges, vnode_to_pnode is custom too:
unsigned int pnode = vnode_to_pnode[vnode]

if ( pnode != XC_NUMA_NO_NODE )  // vnode maps to a physical NUMA node:
    // XENMEMF_exact_node: (XENMEMF_node(n) | XENMEMF_exact_node_request)
    new_memflags |= XENMEMF_exact_node(pnode);
```

This means, to allocate memory in a specific NUMA node,
this is needed:
- Populate-On-Demand (POD) must not be used (`target_pages == total_pages`)
- The sum of the `vmemranges` equals `dom->total_pages`
- `dom->vmemranges` must be passed with a `nid`
- `dom->vnode_to_pnode` must be passed, the `nid` must map to the pNUMA node to allocate on.
- `dom->nr_vmemranges` and `dom->nr_vnodes` must be set accordingly

For the allocation of each vmemrange (extent), a call
to `xc_domain_populate_physmap()` is used.

It calls the `XENMEM_populate_physmap` hypercall for each group of extents to allocate.

See [populate_physmap.md](populate_physmap.md) for the implementation of it.

## Other callers of the `meminit()` calls

`libxl` calls `xc_dom_boot_mem_init()`
using `libxl__build_dom()` from
[init-xenstore-domain.c/build()](https://github.com/xenserver-next/xen/blob/xenguest/tools/helpers/init-xenstore-domain.c#L262).

[Up](../memory_alloc.md)