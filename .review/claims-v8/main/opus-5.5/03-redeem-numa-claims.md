# 03 - xen/mm: redeem per-node claims for allocations

Commit `4b6db7e25a` (`aa8ac0eee5` before the rebase; message and tree unchanged).

**Result:** no change needed. One optional comment suggestion.

## Code review

- `alloc_heap_pages()` redeems `min(d->outstanding_pages, request)` pages:
  - first the claim on the allocated node,
  - then the host-wide claim (`domain_release_host_claims()`),
  - then claims on other nodes (`domain_reduce_node_claims()`),
  - in the order the message gives.

- The last step cannot trip its `ASSERT(released == pages)`:
  - a remainder is left only when the host-wide claim is used up,
  - and then it is at most the sum of the remaining node claims.

- Without node claims:
  - step 1 returns 0,
  - step 2 redeems everything as before,
  - and step 3 gets 0,
  - so "No functional change" holds.

## Considered, not edited

- Earlier reviews judged the three one-line step comments a matter of taste.
