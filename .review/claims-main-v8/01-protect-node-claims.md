# 01 - xen/mm: protect NUMA node-specific claims in get_free_buddy()

Commit `711281c9df`.

**Result:** code correct. One commit message fix (applied, F2).

## Code review

- `get_free_buddy()` now computes what a node can give to the allocation as
  `node_avail_pages[node] - node_claimed_pages[node]`, clamped at 0, plus
  `d->claims[node]` for a ref-counted allocation of a domain that has node
  claims. The node is skipped when that is below `1UL << order`.
- "No functional change" holds. Nothing sets `d->claims` or
  `node_claimed_pages[]` yet, so `available == node_avail_pages[node]`.
  `node_avail_pages[]` moves in lockstep with `avail[node][zone]`
  (allocation, offlining, free). When it is below `1UL << order`, every
  `avail[node][zone]` is too, and the zone loop would have failed anyway.
  The new test is a pure shortcut.
- The clamp is needed: `XEN_SYSCTL_page_offline_op` can reduce free memory
  below the outstanding claims, and the unsigned subtraction would wrap.
  The "Changes in v8" bullet says so.
- `MEMF_no_refcount` allocations get no credit, as the commit message says.
- `d->claims[node]` is indexed with a node below `MAX_NUMNODES`: the
  requested node is checked before the loop, and the `next_node:` code
  returns NULL instead of continuing with an out-of-range node. It is read
  under `heap_lock`, like `node_claimed_pages[]`.
- Mechanics: subject 61 columns, body within 75, no trailing whitespace or
  tabs, tag order correct (`Assisted-by:` directly before Bernhard's
  `Signed-off-by:`, after Roger's).

## Edits applied

### Notes bullet contradicts "Changes in v8" (commit message, applied)

The Notes said that, aside from refactoring, the method "has remained
unchanged since v5". The same message lists, under "Changes in v8", "Replace
an assertion because XEN_SYSCTL_page_offline_op can reduce free memory below
outstanding claims". That is a behaviour change of the `available`
computation (clamp instead of assertion), not a refactoring. A reader sees
two statements that cannot both be true.

```diff
--- a/50bf73699b (message)
+++ b/711281c9df (message)
@@ -30,5 +30,6 @@
   been tested and is in production in XenServer 9.
 - It was updated in v5 to track per-node claims in an array rather than
   supporting only one NUMA node.
-- Aside from refactoring, it has remained unchanged since v5.
+- Aside from refactoring and the assertion replacement, it has remained
+  unchanged since v5.

```

## Considered, not edited

- Formula `max(0, F - C) + c` versus `max(0, F - C + c)` (F: free, C: all
  node claims, c: the domain's claim). They differ only when claims are
  oversubscribed after offlining. The zone loop still verifies that real free
  pages exist, so the more permissive gate is safe. Defensible, and it is a
  design choice, not a defect.
