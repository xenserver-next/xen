.. SPDX-License-Identifier: CC-BY-4.0

Claim Consumption
-----------------

After a successful allocation, Xen releases claims in the same critical region
that updates the free-page counters. This avoids transient inconsistencies in
the amount of free unclaimed memory.

The release logic follows the implementation in ``release_claims()``:

1. Consume the allocation from ``d->global_claims`` (up to its size)

2. Consume the allocation from ``d->claims[node]`` (up to its size)
   and the sum of all per-node claims of the domain in ``d->node_claims``.

3. If the allocation exceeded ``d->claims[node]``, the remaining pages
   must be consumed from other ``d->claims[node]`` entries to satisfy
   the invariants of:
   excess from other node claims.

   This is important when the allocator satisfies a request from a node
   that was not fully covered by that domain's node-local claims:

   In that case, the domain has gained real pages without consuming an
   equal amount of node-local claim on the target node.

   Trimming the remaining node claims keeps the total amount of memory
   dedicated to the domain bounded by its configured limits instead of
   allowing populated pages plus outstanding claims to grow unchecked.
