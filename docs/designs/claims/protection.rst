.. SPDX-License-Identifier: CC-BY-4.0

Protection of claims
--------------------

Claimed memory must be protected from unrelated allocations while still being
usable by the domain that owns the claims.

The allocator therefore performs two checks.

Global check
^^^^^^^^^^^^

``alloc_heap_pages()`` first verifies that the request fits in the global pool
after accounting for claims. The request is permitted if either:

- Enough unclaimed memory exists globally
- The requesting domain's own outstanding claims cover the shortfall.

For this check, the domain's applicable claim is:
``d->global_claims + d->node_claims``

This means the domain receives credit for the complete claim set it owns,
whether the reservation was made globally, per node, or as a combination of
both.

Node check
^^^^^^^^^^

When the allocator searches a specific NUMA node in ``get_free_buddy()``, it
performs an additional node-local check before examining that node's buddy
lists.

For this check, the applicable claim is only: ``d->claims[node]``

This ensures that node-local reservations only grant credit on the nodes where
they were actually made. If a node is fully consumed by other domains' claims,
the allocator skips it and tries another node unless the caller requested an
exact node.
