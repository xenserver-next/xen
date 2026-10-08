# 07 - xen/domctl: add XEN_DOMCTL_get_memory_claims

Commit `5fa925397b` (`c9e46847a9` before the rebase; message and tree unchanged).

**Result:** no change needed.

## Code review

- The case sits in the lockless switch after `xsm_domctl()`, next to `XEN_DOMCTL_getvcpuinfo`, as the message says:
  - `d` is RCU-locked.

- `domain_get_claim_entries()` reads `d->claims` under `heap_lock`:
  - The release path detaches the array under `heap_lock` and frees it later,
  - so the reader never sees a freed array.

- Each returned entry is a compound literal:
  - so `pad` is zero and no stack or heap data leaks.
  - Only entries up to the capacity are written.

- A capacity of 0 gets `ZERO_BLOCK_PTR` from `xvmalloc_array()`:
  - which `xvfree()` accepts,
  - and `copy_to_guest()` of 0 entries reads nothing.

- On -ENOBUFS, `copyback` is set:
  - so the caller gets the needed count.
  - The capacity clamp only limits the allocation.

- FLASK: `getdomaininfo`, with the `access_vectors` comment updated.

## Considered, not edited

- The local `claim` could be `request.claim`:
  - but then the `copy_to_guest()` line would exceed 79 columns.

- `copyback` could be set by the caller instead of being passed in:
  - that is taste.

- A dedicated FLASK permission instead of `getdomaininfo` is a policy question for the FLASK maintainer:
  - not a defect.
