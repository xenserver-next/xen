.. SPDX-License-Identifier: CC-BY-4.0

##################
Claim Installation
##################

**********
Claim sets
**********

A claim set is an array of :c:expr:`memory_claim_t` entries.

.. c:type:: memory_claim_t

   The `typedef`` for :c:expr:`xen_memory_claim`,
   for passing an element of a claim set to the hypervisor.

.. c:struct:: xen_memory_claim

   Underlying structure for passing claim sets to the hypervisor.

   This structure represents an individual claim entry in a claim set.
   It specifies the number of pages claimed and the target of the claim,
   which can be a specific NUMA node or a special value for floating claims.

   The structure includes padding for future expansion, and it is important
   to zero-initialise it or use designated initializers to ensure forward
   compatibility. Members are as follows:

   .. c:member:: uint64_aligned_t pages

      Number of pages for this claim entry.

   .. c:member:: uint32_t cmd

      Reserved for future use, must be 0 for forward compatibility.

   .. c:member:: uint32_t target

      The target of the claim entry. It can be a special selector which could
      include flags and additional information or simply a NUMA node ID.

      The initially supported special selector is:

      :c:expr:`XEN_DOMCTL_CLAIM_MEMORY_TOTAL` for the total claim target.

      When used in a single-entry claim set, this is equivalent to
      the legacy NUMA-unaware claim which is not bound to any node.

      It is used for compatibility with existing :term:`domain builders`
      and for use cases where a domain is not NUMA-affine.

      For backwards compatibility, the number of pages passed to it is
      interpreted as the total memory target for the domain, and existing
      allocations for the guest's memory map are subtracted from it to
      determine the domain's new total floating outstanding claim,
      so that the semantics of the legacy claim are preserved.

      This can also be desirable when the domain builder needs some
      fallback to non-preferred nodes when the memory on the preferred
      nodes is not sufficient to cover all of its needs, but the host's
      memory pool has sufficient free memory to cover the node's shortfall.

.. c:type:: uint64_aligned_t

   64-bit unsigned integer type with alignment requirements suitable for
   representing page counts in the claim structure.

**********************
Claim set installation
**********************

Claim set installation is invoked via :c:expr:`XEN_DOMCTL_claim_memory` and
:ref:`designs/claims/implementation:domain_set_node_claims()` implements
the claim set installation logic.

Claim sets using
:c:expr:`XEN_DOMCTL_CLAIM_MEMORY_LEGACY` are dispatched to
:ref:`designs/claims/implementation:domain_set_outstanding_pages()`
for the legacy claim installation logic.

See :doc:`accounting` for details on the claims accounting state.

*************************
Legacy claim installation
*************************

Legacy claims are set via the :ref:`XENMEM_claim_pages` hypercall command.

.. note:: The legacy path is deprecated.
   Use :c:expr:`XEN_DOMCTL_claim_memory` for new code.
