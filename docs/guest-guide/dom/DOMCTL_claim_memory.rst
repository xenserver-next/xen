.. SPDX-License-Identifier: CC-BY-4.0
.. _XEN_DOMCTL_claim_memory:

XEN_DOMCTL_claim_memory
=======================

This **domctl** command allows a privileged guest to stake a memory claim
for a domain identical to :ref:`XENMEM_claim_pages`, but with support for
NUMA-aware memory claims.

A call with a node argument of ``XEN_DOMCTL_CLAIM_MEMORY_NO_NODE`` stakes
a claim for host memory, exactly like :ref:`XENMEM_claim_pages` does.

NUMA-aware memory claims
------------------------

**What:** NUMA-aware memory claims are an extension of host-wide claims
towards the memory of specific NUMA nodes.

**Why:** Running a domain locally to a NUMA node can provide better performance
due to improved memory locality. By claiming memory on specific NUMA nodes,
toolstacks can ensure that they will be able to allocate memory for the domain
on those nodes. This can reduce latency for the new guest domain and improve
overall performance due to reduced cross-node memory access and NUMA
interconnect utilisation.

**How:** NUMA claims behave identically to a host claim,
except that the call claims memory on the specified NUMA node(s).

**Note:** This hypercall command supports multiple claims for future expansion
possibilities. At the moment, the infrastructure supports a single claim entry
(either a NUMA-aware or host-wide claim).

Implementation notes
--------------------

As described in :ref:`XENMEM_claim_pages`, Xen keeps track of the amount
of claimed pages in the domain's ``d->outstanding_pages`` counter.

Xen declares a NUMA-aware claim by assigning ``d->claim_node`` to a NUMA node,
which indicates that the domain has claimed memory on that NUMA node.

To support setting multiple claims, `d->claim_node` could be replaced
by a table of outstanding pages per NUMA node. The specific implementation
of this table is to be discussed for future expansion.

API example (libxc)
-------------------
The following example demonstrates how a toolstack can claim memory before
building the domain and then releasing the claim once the memory population
is complete.

.. code-block:: C

  #include <xenctrl.h>

  int claim_guest_memory(xc_interface *xch, uint32_t domid,
                         uint64_t nr_pages)
  {
      memory_claim_t claim = {
        .nr_pages = nr_pages,
        .node = 0,  /* Claim memory on NUMA node 0 */
      };

      /* Claim memory from NUMA node 0 for the domain build. */
      return xc_domain_claim_memory(xch, domid, 1, &claim);
  }

  int release_claim(xc_interface *xch, uint32_t domid)
  {
      memory_claim_t claim = {
        .nr_pages = 0,  /* Release the claimed memory */
        .node = XEN_DOMCTL_CLAIM_MEMORY_NO_NODE,
      };

      /* Release any remaining claim once population is done. */
      return xc_domain_claim_memory(xch, domid, 1, &claim);
  }