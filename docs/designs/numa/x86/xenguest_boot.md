# NUMA-aware memory allocation in X86 meminit_hvm()
## Example entry point: xenguest
### Domain creation using xenguest / libxenguest from XAPI

When the XenServer/XCP-NG program xenguest is called with
`--mode hvm_build`, it calls its `do_hvm_build()` function,
it expects these command line arguments:

- domid (must be passed before `--mode hvm_build`)
- mem_max_mib
- mem_start_mib
- image
- store_port
- store_domid
- console_port
- console_domid

https://github.com/xenserver-next/xen/blob/xenguest/tools/xenguest/xenguest.c#L499

Both functions call the `xenguest` function `stub_xc_hvm_build()`
and pass these arguments.

https://github.com/xenserver-next/xen/blob/xenguest/tools/xenguest/xenguest_stubs.c#L1530

## `stub_xc_hvm_build()`

It starts the HVM/PVH domain creation by filling out the fields of `struct flags`
and `struct xc_dom_image`.

## `hvm_build_setup_mem()`

Gets `struct xc_dom_image *dom`, `max_mem_mib`, and
`max_start_mib`. Calculates start and size of most parts
of the domain's memory maps, taking memory holes for I/O
into account, e.g. `mmio_size` and `mmio_start`.

It then uses those to calculate lowmem_end and highmem_end.
and then calls `xc_dom_boot_mem_init()`:

##  `xc_dom_boot_mem_init()`

In all cases, `xc_dom_boot_mem_init()` is called:

https://github.com/xen-project/xen/blob/master/tools/libs/guest/xg_dom_boot.c#L110

Except error handling and tracing, all it does is to call the
architecture-specific `meminit` hook for the domain type:

```c
rc = dom->arch_hooks->meminit(dom);
```

This calls the [meminit_hvm()](meminit_hvm.md) libxc function.


[Up](../memory_alloc.md)