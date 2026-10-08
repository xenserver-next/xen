# 00 - Cover letter: xen/mm: Introduce handling of multi-node NUMA claim sets

**Result:** consistent with the seven patches.

## Checked against the series

- "The host-wide XENMEM_claim_pages infrastructure is preserved and reused":
  - patch 4 keeps `domain_set_outstanding_pages()`
  - and reuses `domain_set_outstanding_pages(d, 0)` to release all claims.

- Every bullet of "Changes in v8" has a counterpart in the code:

  | Bullet | Where |
  |--------|-------|
  | Smaller patches, bisectable in the given order | patches 1-7; each message repeats the first bullet. Builds were not re-run, a previous reviewer ran them |
  | Claims array on demand, not in `struct domain` | `xvzalloc_array()` in `domain_set_claim_entries()` (patch 3); `d->claims` is a pointer (patch 1) |
  | Replacing claims removed | `domain_install_claims()` returns -EINVAL when `d->outstanding_pages` is set (patch 3) |
  | Installation split into smaller functions | `domain_validate_claim_request()`, `check_memory_for_claim_request()`, `domain_install_claims()` (patch 3) |
  | Defer changes not needed for the MVP | patch 4 keeps `domain_set_outstanding_pages()` "until a later patch series" |
