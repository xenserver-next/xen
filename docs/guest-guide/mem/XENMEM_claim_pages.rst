.. SPDX-License-Identifier: CC-BY-4.0
.. _XENMEM_claim_pages:

XENMEM_claim_pages
==================

This **xenmem** command allows a privileged guest to stake a memory claim for a
domain, identical to :ref:`XEN_DOMCTL_claim_memory`, which is extended for
NUMA-aware claims. XENMEM_claim_pages should not be used for new code and is
deprecated. :ref:`XEN_DOMCTL_claim_memory` provides the same claims semantics.

See :ref:`hypervisor-guide` > :ref:`designs` > :ref:`designs-claims`
for details on the API semantics and implementation details of the claims
infrastructure of the Xen buddy allocator backing this hypercall.

API example (C code using libxenctrl)
-------------------------------------

The following example demonstrates how a toolstack can claim memory before
building the domain and then releasing the claim once the memory population
is complete.

Simplified pseudocode for building a domain with claimed memory:

.. code-block:: C

  #include <xenctrl.h>
  ...
      /* Claim memory for the domain build. */
      ret = xc_domain_claim_pages(xch, domid, nr_pages);

      /* Populate the physmap of the domain. */
      ret = xc_domain_populate_physmap(xch, domid, ...);

      /* Release any remaining claim after populating the domain memory. */
      ret = xc_domain_claim_pages(xch, domid, 0);

      /* Unpause the domain to allow it to run. */
      ret = xc_unpause_domain(xch, domid);
