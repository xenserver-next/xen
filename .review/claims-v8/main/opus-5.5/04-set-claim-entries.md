# 04 - xen/mm: add domain_set_claim_entries() for NUMA memory claims

Commit `8893ae903b` (`6baec09fe9` before the rebase; message and tree unchanged).

**Result:** no change needed.

## Code review

- `domain_validate_claim_request()` runs under `d->page_alloc_lock` and cannot overflow:
  - the 32-bit wrap guard comment is accurate.

- `domain_install_claims()` takes `heap_lock`:
  - rejects a domain with outstanding claims,
  - calls `check_memory_for_claim_request()`,
  - and updates all counters in the same locked region,
  - so installing the set is atomic.

- A host-only request installs a NULL `d->claims`:
  - the loop skips host entries, so it never writes through NULL.
  - The swapped-out array only holds zeros,
  - and is freed after the locks are dropped,
  - as is the array that the release path of patch 2 detaches.
  - The patch is self-contained.

- `xvzalloc_array()` runs under `d->page_alloc_lock` only:
  - That is safe: the xmem pool lock is dropped before more memory is requested.

- The "next one" reference is below `---`.

## Considered, not edited

- The `0x80000000U` literal for the reserved bit, "duplicated" vs "duplicate", and comma splices are taste.
