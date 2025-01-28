# Populating a domain's "physical" memory

## Hypercall: `XENMEM_populate_physmap `
### `memory_op()`
The entry point for al `XENMEM` phypercalls is the function `memory_op()`:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L1395

`memory_op()` checks the hypercall command. If the command is
- XENMEM_increase_reservation,
- XENMEM_decrease_reservation, or
- XENMEM_populate_physmap,
  it copies the arguments from the calling guest and calls
  `construct_memop_from_reservation()`. Code:
  https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L1424
  If if returns true, depending on the hypercall command, it calls
  - `increase_reservation()`,
  - `decrease_reservation()`, or
  - `populate_physmap`
  using the `struct memop_args` populated from the given `xen_memory_reservation`.

#### `construct_memop_from_reservation()`

Populates `struct memop_args` using the `xen_memory_reservation` that
the calling domain passed to the one of the called hypercalls.

https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L1022

 `construct_memop_from_reservation()` copies the passed
parameters from `xen_memory_reservation`:
- `extent_start`
- `nr_extents`
- `extent_order`
- `mem_flags`
  - Converts `xen_memory_reservation->mem_flags->address_bits` to
    `MEMF_bits` set in `memop_args->memflags`

- If a `vnode` was passed, for `vnuma` and if enabled, it passes the `pnode`:
  - `XENMEMF_vnode` is passed in `xen_memory_reservation->mem_flags`,
  - `memop_args->domain->vnuma` is set, and
  - `memop_args->domain->vnuma->nr_vnodes` is != `0`,
  it gets the `vnode` from `xen_memory_reservation->mem_flags`.
  When `memop_args->domain->vnode_to_pnode[vnode]` is not `NUMA_NO_NODE`,
  - it:
    - converts the `pnode` to `memop_args->memflags`
    - converts a `XENMEMF_exact_node_request` to `memop_args->memflags`

- If `XENMEMF_vnode` was not set in the passed `xen_memory_reservation`,
  it calls `propagate_node()` to convert `mem_flags` to `memflags`.

Code:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L1048

### `propagate_node()`

- If the node in `xen_memory_reservation->mem_flags` is `NUMA_NO_NODE`,
  it returns `true` (there is nothing to propagate)
- If the domain is running the function is Dom0 or a privileged domain:
  - If the node is >= `MAX_NUMNODES`, return `false`
  - Else, convert the `node` and XENMEMF_exact_node_request to `memflags`
- Otherwise, if `XENMEMF_exact_node_request` is set, return `false`.
  This means, to propagate the `XENMEMF_exact_node_request` and the node,
  the propagation fails.
- Otherwise, return `true` (no `XENMEMF_exact_node_request` propagate)

Code:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L524

### `memory_op()` then calls `populate_physmap()` to populate the memory

`memory_op()` calls `populate_physmap()` here:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L1458
->
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L159

#### `populate_physmap()`

`populate_physmap()` loops over the extents in the reservation it shall populate:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L197

For each  extents in the reservation, it calls
`alloc_domheap_pages(d, a->extent_order, a->memflags)`:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L275

#### Function in `xen/common/page_alloc.c`: `alloc_domheap_pages()`

[alloc_domheap_pages()](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L2641)
calls
[alloc_heap_pages()](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L2673).

#### Function in `xen/common/page_alloc.c`: `alloc_heap_pages()`

[alloc_heap_pages()](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L968)
calls
[ get_free_buddy()](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L1005)

#### Description of [`get_free_buddy()`](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L855) (in `xen/common/page_alloc.c`:)<a id='get_free_buddy'></a>

Main function of the Xen buddy allocator:<br>
If possible, it tries to find the best NUMA node and memory zone to allocate from.

Input parameters:
- Zones to allocate from (starts at `zone_hi` until `zone_lo`)
- Page order (size of the page)
  - populate_physmap() callers start with 1GB pages and fall back
- Domain struct

Its first attempt is to find a page of matching page order
on the requested NUMA node(s).

If that does not check out, looks to breaking higher orders,
and if that fails too, it lowers the zone until `zone_lo`.

It does not attempt to use not scrubbed pages, but when `memflags`
tell it `MEMF_no_scrub`, it uses `check_and_stop_scrub(pg)` on 4k
pages to prevent breaking higher order pages instead.

If all fails, it [checks if other NUMA nodes shall be tried (line 933-955)](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#993):


vNUMA functionality of [`get_free_buddy()`](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L855):

Intro:
With vNUMA, specific memory ranges are mapped from specific NUMA nodes.
Thus, for vNUMA domains, the calling functions have to pass one specific
NUMA node to allocate from, and they would also set `MEMF_exact_node`.

If a NUMA node was specified in the passed
[memflags](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L860),
allocate from it, if possible.

If `MEMF_exact_node` was set in the passed memflags,
it does not fall back to generic node affinties.
Otherwise, it falls back to the next fallback.

Fallback: Generic NUMA functionality of
[`get_free_buddy()`](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L855):

For the generic NUMA affinity, the domain should have one or more
NUMA nodes in its  `struct domain->node_affinity` field when this
function is called.

If node affinities are set up for the domain, it tries
to allocate from the NUMA nodes `struct domain->node_affinity` field
in a round-robin way using the next NUMA node after the previous
NUMA node the domain allocated from.

Otherwise, the thunction falls back to the default fallback.

Default fallback: Generic round-robin allocation:

When the above did not apply or fallback was non excluded using
by not setting `MEMF_exact_node` in `memflags`, then:

All remaining nodes are attempted in a rond-robin way using the
next NUMA node after the NUMA node of the previous NUMA node
that the domain allocated memory from.
