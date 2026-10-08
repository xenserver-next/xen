# 01 - xen/mm: protect per-node claims in get_free_buddy()

**Result:** no change needed.

## Code review

- `get_free_buddy()` skips a node when its unclaimed free memory is below the request:
  - unclaimed free memory is `node_avail_pages[node] - node_claimed_pages[node]`, clamped at 0,
  - plus the domain's claim on that node.
  - Only ref-counted allocations of a domain with `d->claims` get the credit,
  - as the `MEMF_no_refcount` paragraph says.

- "No functional change" holds:
  - without node claims, the check compares `node_avail_pages[node]`, the sum over the node's zones, with the request.
  - It only skips nodes that the zone loop would reject as well.

- `goto next_node` reaches the existing `MEMF_exact_node` check:
  - so an exact-node allocation fails,
  - as it does for a node without enough memory.

## Considered, not edited

- The availability formula max(0, F - C) + c was accepted by an earlier review.
