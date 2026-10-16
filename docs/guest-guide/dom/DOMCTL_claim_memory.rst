.. SPDX-License-Identifier: CC-BY-4.0

claim_memory
************

 .. c:macro:: XEN_DOMCTL_set_memory_claims

  Set host-wide and per-node memory claims for a domain during its creation
  phase. Claims protect the reserved memory from allocations that cannot
  redeem them. A non-empty set is accepted only when the domain has no
  outstanding claims. Passing an empty array releases all claims, regardless
  of the domain's creation state.

 .. c:macro:: XEN_DOMCTL_get_memory_claims

  Retrieve the current host-wide and per-node claims of a domain. The returned
  host-wide entry, if present, comes first, followed by per-node entries in
  ascending node order.

See :ref:`designs/claims/installation:Claims installation` for the
installation rules and :ref:`designs/claims/protection` for allocator behavior.

Hypercall API
-------------

See :ref:`designs/claims/installation:Claim sets` for the claim entry
structure.

Definitions
^^^^^^^^^^^

Target selectors
~~~~~~~~~~~~~~~~
  .. c:macro:: XEN_DOMCTL_MEMORY_CLAIM_TARGET_HOST

    Special target selector for host-wide claims,
    which can be satisfied from any NUMA node.

    Other target values with bit 31 set are reserved. Node targets must
    identify distinct online NUMA nodes.

domctl.h structure
^^^^^^^^^^^^^^^^^^

 .. code-block:: C

    typedef struct xen_domctl_memory_claim {
      uint64_aligned_t pages; /* Number of pages to claim */
      uint32_t target;        /* NUMA node or host-wide target */
      uint32_t pad;           /* Must be zero */
    } xen_domctl_memory_claim_t;
    DEFINE_XEN_GUEST_HANDLE(xen_domctl_memory_claim_t);

    #define XEN_DOMCTL_MEMORY_CLAIM_TARGET_HOST 0x80000000U

    struct xen_domctl_memory_claims {
      XEN_GUEST_HANDLE_64(xen_domctl_memory_claim_t) claims;
      uint32_t nr_claims;
      uint32_t pad; /* Must be zero */
    };

    /* XEN_DOMCTL_set_memory_claims and XEN_DOMCTL_get_memory_claims */
    /* Each domctl uses struct xen_domctl_memory_claims as its argument. */


C API by libxenctrl
-------------------

 .. c:function:: int xc_domain_set_memory_claims(xch, domid, claims, nr_claims)

   Atomically set host-wide and per-node claims before domain creation
   finishes. The domain must have no outstanding claims. Passing zero for
   ``nr_claims`` releases all claims regardless of creation state.

 .. c:function:: int xc_domain_get_memory_claims(xch, domid, claims, nr_claims)

   Retrieve the current claims. ``*nr_claims`` is the buffer capacity on input
   and the number of entries on output. If the buffer is too small, the call
   fails with ``ENOBUFS`` and updates the required count without modifying the
   entries. Passing zero capacity and a ``NULL`` buffer queries the count.

Both functions are part of :term:`libxenctrl`. The caller must serialize
claim installation with allocations for the domain, including completion of
any allocation continuation.

C API usage example
^^^^^^^^^^^^^^^^^^^

The example installs a host-wide claim and a per-node claim. Claim entries
must be unique, request at least one page, and have zero padding. A second
non-empty set cannot replace the first; pass an empty array to release claims.

 .. code-block:: C

  #include <xenctrl.h>

  int install_example_claims(xc_interface *xch, uint32_t domid)
  {
      xen_domctl_memory_claim_t claims[] = {
          { .pages = 1024, .target = 0 },
          { .pages = 512, .target = XEN_DOMCTL_MEMORY_CLAIM_TARGET_HOST },
      };
      int rc;

      rc = xc_domain_set_memory_claims(xch, domid, claims,
                                       ARRAY_SIZE(claims));
      if ( rc )
          return rc;

      /* Populate the domain before creation finishes. */
      rc = xc_domain_populate_physmap(xch, domid, /* ... */);
      if ( rc )
          return rc;

      return xc_domain_set_memory_claims(xch, domid, NULL, 0);
  }

Call sequence diagram
---------------------

 The following sequence diagram illustrates the call flow for setting and
 redeeming claims during a domain build:

 .. mermaid:: DOMCTL_claim_memory-seqdia.mmd
   :caption: Sequence diagram: Call flow for claiming memory for a domain

Claim workflow
--------------

 This diagram illustrates a workflow for claiming and populating memory:

 .. mermaid:: DOMCTL_claim_memory-workflow.mmd
   :caption: Workflow diagram: Claiming and populating memory for a domain

Used functions & data structures
--------------------------------

 This diagram illustrates the key functions and data structures involved in
 installing claims via the set/get memory claims domctls:

 .. mermaid:: DOMCTL_claim_memory-data.mmd
   :caption: Diagram: Function and data relationships for installing claims
