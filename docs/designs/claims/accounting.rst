.. SPDX-License-Identifier: CC-BY-4.0

Claims Accounting State
-----------------------

Five pieces of state participate in the accounting:

1. ``d->global_claims``
   The domain's global claim. This is the legacy claim for old callers and
   the optional node-flexible claim for NUMA-aware callers.

2. ``d->node_claims``
   The sum of all claims in ``d->claims[node]`` for the domain.

3. ``d->claims[node]``
   The domain's claim on a particular NUMA node.

4. ``outstanding_claims``
   The sum of all domains' outstanding claims, both global and node-local.
   It is the sum of all domains' ``d->global_claims`` plus all domains'
   ``d->node_claims``.

5. ``node_outstanding_claims[node]``
   The sum or share of all domains' claims on a specific NUMA node.

The key invariants are:

- ``d->node_claims`` equals the sum of ``d->claims[node]`` of that domain.

- ``node_outstanding_claims[node]`` equals the sum of all domains'
  ``d->claims[node]`` for that node.

- ``outstanding_claims`` equals the sum of
  ``d->global_claims + d->node_claims`` over all domains.

- ``outstanding_claims`` also equals the sum of all nodes'
  ``node_outstanding_claims[node]`` because each node's total claims
  are included in the global total.

This diagram illustrates the claims accounting state and the invariants:

.. mermaid:: invariants.mmd
  :caption: Diagram: Claims accounting state and invariants
