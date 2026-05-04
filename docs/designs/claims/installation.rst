.. SPDX-License-Identifier: CC-BY-4.0

Installation
############

**********
Claim sets
**********

A claim set is an array of :c:type:`memory_claim_t` entries.

.. c:type:: memory_claim_t

   The ``typedef`` for :c:type:`xen_memory_claim`, used for
   passing an array of claim set entries to the hypervisor.

.. c:struct:: xen_memory_claim

   Underlying structure for passing claim sets to the hypervisor.

   This structure represents an individual claim entry in a claim set.
   It specifies the number of pages claimed and the target of the claim,
   which can be a specific NUMA node or a special value for unpinned claims.

   The structure includes padding for future expansion. It is important to
   zero-initialise it or use designated initialisers to ensure forward
   compatibility. Members are as follows:

   .. c:member:: uint64_aligned_t pages

      Number of pages for this claim entry.

   .. c:member:: uint32_t cmd

      Command field reserved for future use. It must be initialised to 0
      for forward compatibility.

   .. c:member:: uint32_t target


      The target of the claim entry. It can be a special selector, which could
      in the future include flags and additional information, or simply a NUMA
      node ID.

      See :ref:`guest-guide/dom/DOMCTL_claim_memory:Hypercall API`
      for the defined special selectors and their semantics.

.. c:type:: uint64_aligned_t

   64-bit unsigned integer type with alignment requirements suitable for
   representing page counts in the claim structure.

**********************
Claim set installation
**********************


Claim set installation is invoked via :c:macro:`XEN_DOMCTL_claim_memory`, and
:c:func:`domain_install_claim_set()` implements the claim set installation logic.

See :doc:`accounting` for details on the claims accounting state.

*************************
Legacy claim installation
*************************

Legacy claims are set via the :c:macro:`XENMEM_claim_pages` hypercall command.

.. note:: The legacy path is deprecated.
   Use :c:macro:`XEN_DOMCTL_claim_memory` for new code.
