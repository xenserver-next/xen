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