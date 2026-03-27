.. SPDX-License-Identifier: CC-BY-4.0
.. _XENMEM_claim_pages:

XENMEM_claim_pages
==================

.. note:: This API is deprecated;
   Use :ref:`XEN_DOMCTL_claim_memory` for new code.

:ref:`designs/claims/installation:Legacy claim installation` describes
the API for installing legacy claims via this hypercall command.

API example using libxenctrl
----------------------------

The example below claims pages, populates the domain,
and then clears the claim.

.. code-block:: C

  #include <xenctrl.h>

  int build_with_claims(xc_interface *xch, uint32_t domid,
                        unsigned long nr_pages)
  {
      int ret;

      /* Claim pages for the domain build. */
      ret = xc_domain_claim_pages(xch, domid, nr_pages);
      if ( ret < 0 )
          return ret;

      /* Populate the domain's physmap. */
      ret = xc_domain_populate_physmap(xch, domid, /* ... */);
      if ( ret < 0 )
          return ret;

      /* Release any remaining claim after populating the domain memory. */
      ret = xc_domain_claim_pages(xch, domid, 0);
      if ( ret < 0 )
          return ret;

      /* Unpause the domain to allow it to run. */
      return xc_unpause_domain(xch, domid);
  }
