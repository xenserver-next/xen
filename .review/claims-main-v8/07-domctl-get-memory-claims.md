# 06 - xen/domctl: add XEN_DOMCTL_get_memory_claims

Commit `3f556fb7fa` (`899389310d` before the message rewrite, tree identical).

**Result:** code correct. One commit message fix (applied, F7).

## Code review

- `get_memory_claims()` rejects non-zero `pad`, clamps the capacity to
  `MAX_NUMNODES + 1` (one entry per node plus the host-wide one, so the
  clamped capacity is always enough), allocates with `xvmalloc_array()`,
  fills the entries under `heap_lock` through `domain_get_claim_entries()`,
  stores the needed count in `op->nr_entries`, sets `*copyback` and copies to
  the guest only after the lock is dropped.
- With a capacity of 0, `xvmalloc_array()` returns `ZERO_BLOCK_PTR`, which
  is not NULL, and `xvfree()` ignores it. The count query therefore works.
- If the capacity is too small, nothing is written to the array and -ENOBUFS
  is returned. `copyback` is set before the return, and `do_domctl()` copies
  the domctl back regardless of `ret`, so the caller gets the needed count.
  The copy to the guest copies `request.nr_entries` entries, exactly the
  entries that were filled. Each entry is built as a compound literal, so
  `pad` is zero and nothing uninitialised reaches the guest.
- `d->outstanding_pages`, `d->node_claims` and `d->claims` are protected by
  `heap_lock` (see `struct domain`). Every writer holds `heap_lock`, including
  the detach of `d->claims` in `domain_set_outstanding_pages()`, so a reader
  sees either the old array (still allocated, as the free comes after the
  detach) or NULL. Reading under `heap_lock` alone is enough.
- The handler sits in the first `switch` of `do_domctl()`, after
  `xsm_domctl()` and before `domctl_lock_acquire()`, like `getvcpuinfo`.
  The operation only reads state that `heap_lock` protects, so it needs no
  domctl lock. The case ends with `goto domctl_out_unlock_rcuonly`, the same
  as the neighbouring cases.
- Entries are the host-wide claim (only if nonzero), then the node claims in
  ascending node order, as the comment, the commit message and `domctl.h`
  say. The errno list (EINVAL, ENOMEM, ENOBUFS, EFAULT) matches the code.
- FLASK: `current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETDOMAININFO)`, as
  the commit message says, and the comment in `access_vectors` is updated.
- Without FLASK, `xsm_domctl()` defaults to `XSM_PRIV`.

## Considered, not edited

TODO 1:

- The bullet "As it only reads claims of a domain under heap_lock, which
  does not require the domctl lock, handle it without taking the domctl
  lock." is convoluted, but correct and below `---`. Taste.

TODO 2:

- The series adds no test for the new domctls. `tools/tests/mem-claim`
  exists (it exercises `XENMEM_claim_pages`) and is not touched. That is not a defect of this patch; the author or a maintainer may ask for one.
