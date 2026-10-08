# 02 - xen/mm: redeem NUMA node-specific claims for allocations

**Result:** code correct. One commit message fix (applied).

## Code review

- `alloc_heap_pages()` redeems in the order the commit message lists:
  - the claim on the node of the allocated page (`domain_release_node_claims()`),
  - then the host-wide claim (`domain_release_host_claims()`),
  - then claims on other nodes (`domain_reduce_node_claims()`).

- "No functional change" holds:
  - With `d->node_claims == 0`, `domain_release_node_claims()` returns 0 before touching `d->claims`.
  - `domain_release_host_claims()` then releases `min(outstanding_pages, request)`:
    - which is exactly the old two lines.
  - `domain_reduce_node_claims(d, 0)` leaves its loop on the first iteration
  - and the assertion `0 == 0` holds.

- The final assertion `released == pages` holds by derivation:
  - Let `O` be the outstanding pages, `N` the node claims, `H = O - N` the host-wide claim and `r <= O` the pages to redeem.
  - Step 1 releases `a` pages on the node.
  - Step 2 releases `min(r - a, H)`.
  - If anything is left over, `H` was exhausted and the node's own claim is zero:
    - so the leftover is at most `N - a`, the claims on the other nodes.

- Locking:
  - the new helpers assert `heap_lock`.
  - `d->node_claims` is protected by `heap_lock` like `d->outstanding_pages` (see `struct domain` comment).

- `domain_release_node_claims()` checks `d->node_claims` before using `d->claims[node]`:
  - so a NULL `d->claims` is never dereferenced.

- RNC-1 (offline nodes are skipped by `for_each_online_node()`):
  - It is correctly described in the review note:
  - Xen cannot offline nodes.

## Considered, not edited

- Comment "Preserve other node guarantees: consume the local claim first.":
  - the wording could be different,
  - but it is accurate.
  - Taste.
