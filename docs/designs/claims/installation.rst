.. SPDX-License-Identifier: CC-BY-4.0

Claim Installation Paths
------------------------

Legacy claim installation path
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The existing global claim path is deprecated but supported for compatibility
with existing builders and toolstacks and is unchanged in behaviour.
Its semantics are:

- The request contains exactly one claim entry.
- The claim is stored in ``d->global_claims`` and is the delta between the
  requested total and ``domain_tot_pages(d)`` at the time of the installation.
- It cannot update an existing claim in place. Callers must release or reset
  it before making a different legacy claim (or use a claim set to replace it).

Except for handling the edge cases for permitting allocating from unclaimed
memory and offlining pages, the legacy path is functionally unchanged.

A caller can request this path by submitting a claim in two ways:

1. The unmodified single-claim hypercall command ``XENMEM_claim_pages``
2. The new ``domctl`` hypercall command ``XEN_DOMCTL_claim_memory`` for claim
   sets by submitting a claim set using one claim with the special selector
   ``XEN_DOMCTL_CLAIM_MEMORY_LEGACY`` (which is also the internal interface
   to pass the legacy claims to the updated claims installation handling).

Resetting claims using the legacy claim installation path also resets
any claims installed by the claim sets path and vice versa.

See :ref:`designs/claims/implementation:domain_set_outstanding_pages()`
for details on the implementation of the legacy claim installation path.

.. note:: The legacy claim installation path is deprecated but supported for
    compatibility with existing builders and toolstacks and is unchanged in
    behaviour. The claim set installation path is the new path to install
    claims for domains, which supports NUMA-aware claims and replacement
    of existing claims.

Claim set installation path
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The claim set installation path accepts a claim set as an array of
``struct xen_memory_claim``. It is defined as follows:

.. code-block:: C

      struct xen_memory_claim {
            uint64_aligned_t pages;
            uint32_t node;
            uint32_t pad;
      };

The array is a claim set and is installed atomically as the domain's
new claim state. The semantics of the claim set are:

- An optional entry for an amount of global memory as the first entry.
- The remaining entries have to target specific NUMA nodes.
- Each entry replaces the existing claim for its target (global or node)
  and the sum of the entries replaces the total claim for the domain.
- Each node-local claim is strict and guarantees that the claimed amount
  of memory can be allocated from that node, while the global claim is
  flexible and can be allocated from any node.

See :ref:`designs/claims/implementation:domain_set_node_claims()`
for details on the implementation of the claim set installation.

The implementation separates host-wide and node-local accounting:

- ``d->global_claims`` tracks the domain's flexible global claim.
- ``d->node_claims`` tracks the sum of all node-local claims.
- ``d->claims[node]`` tracks the claim for a specific NUMA node.

This separation makes the accounting easier to reason about and allows a
domain to combine strict node-local claims with an additional host-wide
fallback claim for memory that does not need to come from any specific node.

See :doc:`accounting` for details on the claims accounting state
and invariants that the implementation maintains to track the claims
and their relationship to the overall memory state of the system.
