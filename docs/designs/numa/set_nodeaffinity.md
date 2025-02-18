# Setting a Domain's node affinity

## Hypercall: `XEN_DOMCTL_setnodeaffinity`

It can be called from `libxenctrl` and `libxl`

### `libxenctrl`: `xc_domain_node_setaffinity()`

This call requires the `domid` of the created domain and an `xc_nodemap_t`:
```c
int xc_domain_node_setaffinity(xc_interface *xch,
                               uint32_t domid,
                               xc_nodemap_t nodemap)
```

Source: https://github.com/xen-project/xen/blob/master/tools/libs/ctrl/xc_domain.c#L122

### Xen Hypervisor implementation

#### For `setnodeaffinity`, `do_domctl()` calls `domain_set_node_affinity()`

The entry point for al `DOMCTL` phypercalls is the function `do_domctl()`:

When asked for XEN_DOMCTL_setnodeaffinity, it calls `xenctl_bitmap_to_nodemask()`
to convert `&op->u.nodeaffinity.nodemap` to `nodemask_t` and then calls
`domain_set_node_affinity(d, &new_affinity);` with the nodemask:
https://github.com/xen-project/xen/blob/master/xen/common/domctl.c#L516

#### `domain_set_node_affinity()`

Starts at https://github.com/xen-project/xen/blob/master/xen/common/domain.c#L943

If the new nodemap does not intersect the `node_online_map`, it returns `-EINVAL`.

On success, it disables the automatic affinity feature of Xen, where Xen
tries to deduce the affinity of the domain from the affinty of its vCPUs
for this domain and updates the domain's `node_affinity` for memory allocations
using the buddy allocator.

It also calls into the Xen scheduler to notify it of the change.
If the Xen scheduler does not have any vCPUs at that moment,
the Xen scheduler notification does nothing.

However, setting an explicit node_affinity for the domain changes
the NUMA nodes to allocate from before the vCPU affinity is set, and
it could alter the behavior of the scheduler in theory as well.

While this call cannot influence the past, whereas domain_create() already
created the domain and allocated the internal Xen data structures,
the setting node_affinity early can change the course of memory allocations
for the domain.