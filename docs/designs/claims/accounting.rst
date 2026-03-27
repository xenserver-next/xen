.. SPDX-License-Identifier: CC-BY-4.0

Claims Accounting
-----------------

.. note::
   Claims accounting state is only updated while holding the ``heap_lock``.
   See :ref:`designs/claims/accounting:Locking of claims accounting`
   for details on the locks used to protect claims accounting state.

When installing or consuming a domain's claims, the page allocator updates:

- ``d->global_claims``: The domain's (legacy/flexible) global claim.
- ``d->claims[node]``: The domain's claim for a specific NUMA node.

  This uses ``d->claims[MAX_NUMNODES]`` in ``struct domain`` for per-node
  claims, indexed by the node ID. As ``struct domain`` is allocated using
  a dedicated page with more than enough space for it, this is the most
  efficient way to store per-node claims without needing a separate
  allocation and the direct indexing allows for efficient updates
  and checks in the allocator hot paths.

Xen also maintains aggregate state for fast checks in allocator hot paths:

- ``d->node_claims``:
  Sum of ``d->claims[all nodes]`` for the domain.

- ``node_outstanding_claims[node]``:
  The sum of all domains' claims for the specific NUMA node.

- ``outstanding_claims``:
  Sum over all domains of ``d->global_claims + d->node_claims``.

Xen must maintain the following invariants:

- Global claims: ``outstanding_claims`` ≤ ``total_avail_pages``
- Node claims: ``node_outstanding_claims[node]`` ≤ ``node_avail_pages[node]``
- Domain claims:
  ``domain_tot_pages(d) + d->global_claims + d->node_claims``
  ≤ ``d->max_pages``

  See :doc:`consumption` for details on the latter invariant.

Locking of claims accounting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The locks below are used for claims accounting.
The locking order is ``d->page_alloc_lock`` before ``heap_lock``,
consistent with code that calls into the allocator while holding
``d->page_alloc_lock`` and then takes ``heap_lock``.

``heap_lock``
"""""""""""""

``heap_lock`` is taken for all heap operations including claims.
This protects the claims state and invariants from concurrent updates
and ensures that checks in the allocator hot paths see a consistent view
of the claims state.

``d->page_alloc_lock``
""""""""""""""""""""""

``d->page_alloc_lock`` protects ``d->max_pages`` and
``domain_tot_pages(d)``. Both
:ref:`designs/claims/implementation:domain_set_outstanding_pages()` and
:ref:`designs/claims/implementation:domain_set_node_claims()` hold this
lock when checking the domain's ``max_pages`` limit, ensuring the
domain's claims do not exceed it.

Claims Accounting Diagram
^^^^^^^^^^^^^^^^^^^^^^^^^

This diagram illustrates the claims accounting state and the invariants:

.. mermaid:: invariants.mmd
  :caption: Diagram: Claims accounting state and invariants
