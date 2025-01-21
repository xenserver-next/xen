# Populating a domain's "physical" memory

## Hypercall: `XENMEM_populate_physmap `
### `memory_op()` calls `populate_physmap()`
The entry point for al `XENMEM` phypercalls is the function `memory_op()`:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L1395

It copies the arguments from the calling guest and calls `populate_physmap()`:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L1458
->
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L159

### `populate_physmap()`

`populate_physmap()` loops over the extents in the reservation it shall populate:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L197

For each  extents in the reservation, it calls
`alloc_domheap_pages(d, a->extent_order, a->memflags)`:
https://github.com/xen-project/xen/blob/master/xen/common/memory.c#L275

### `alloc_domheap_pages()`

[alloc_domheap_pages()](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L2641)
calls
[alloc_heap_pages](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L2673).

### `alloc_heap_pages()`

[alloc_heap_pages()](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L968)
calls
[ get_free_buddy()](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L1005)

### `get_free_buddy()`

[`get_free_buddy()`](https://github.com/xen-project/xen/blob/master/xen/common/page_alloc.c#L855)

allocates pages from all NUMA nodes in node_online_map, in a round-robin way
limited by domains node_affinity field.

If the passed memflags contain a NUMA node, it is used instead.