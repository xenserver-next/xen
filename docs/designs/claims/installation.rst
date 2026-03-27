.. SPDX-License-Identifier: CC-BY-4.0

Claim Installation Paths
------------------------

Claim set installation
^^^^^^^^^^^^^^^^^^^^^^

Claim sets can be installed via :ref:`XEN_DOMCTL_claim_memory`. This API
atomically installs a set of claims across NUMA nodes, with an optional
global fallback. Claims are provided as an array of ``memory_claim_t``
structures:

.. code-block:: C

  struct xen_memory_claim {
    uint64_aligned_t pages;
    uint32_t node;
    uint32_t pad;
  };
  typedef struct xen_memory_claim memory_claim_t;

- ``node`` specifies a NUMA node or
  ``XEN_DOMCTL_CLAIM_MEMORY_GLOBAL`` for a global claim.
- ``pages`` specifies the number of pages for that claim entry.
- ``pad`` is reserved for future use and must be set to 0.
- Passing an array with all entries having ``pages == 0`` clears any
  claims installed for the domain.

See :ref:`designs/claims/implementation:domain_set_node_claims()` for the
steps of claim set installation. See :doc:`accounting` for details on the
claims accounting state.

Legacy claim installation
^^^^^^^^^^^^^^^^^^^^^^^^^

.. note:: The legacy path is deprecated.
   Use :ref:`XEN_DOMCTL_claim_memory` for new code.

Legacy claims are set via the :ref:`XENMEM_claim_pages` command,
implemented by
:ref:`designs/claims/implementation:domain_set_outstanding_pages()`,
with the following semantics:

- The request contains exactly one global claim entry.
- It sets ``d->global_claims = <requested_pages> - domain_tot_pages(d)``.
- Passing ``pages == 0`` clears any claims installed for the domain.

Aside from the edge cases for allocations exceeding claims and
offlining pages, the legacy path is functionally unchanged.
