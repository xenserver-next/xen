.. SPDX-License-Identifier: CC-BY-4.0

Protection
##########

.. contents:: Table of Contents
    :backlinks: entry
    :local:

Claimed memory must be protected from allocations without applicable claims
while remaining available to allocations with applicable claims.

Claims exist as long as they are outstanding, which is from the moment they
are installed until they are redeemed by allocations.

During this time, they are a commitment of memory to a domain, and the
hypervisor must ensure that this commitment is respected by protecting
claimed memory from being allocated without redeeming applicable claims.

Redeeming claims is the process of applying a portion of the claims of
a domain to an allocation to allow the allocation to proceed by exchanging
the claim for the allocated memory, so that the allocation can use the
claimed memory and the portion of the claim used for the allocation is
no longer outstanding.

For example, if a domain has an outstanding claim of 100 pages on a node,
and it redeems 20 pages of that claim for an allocation, the domain would
have 80 pages of that claim still outstanding, and the allocation would be
satisfied using the claimed memory, so the domain can use that allocated
memory and the claim would be reduced by the redeemed amount.

For the protection of claims, the allocator performs checks to ensure that
claimed memory is not allocated without redeeming applicable claims, while
still allowing the claiming domain to allocate claimed memory by redeeming
claims.

When the system is not under heavy memory pressure and not fully-claimed,
the allocator can satisfy allocation requests using unclaimed memory.

However, when the system is under heavy memory pressure or nearly fully-claimed,
the checks for protecting claims become critical to ensure that claimed memory
is not allocated without redeeming applicable claims.

*********************************
Reference-counting of allocations
*********************************

Claims protection distinguishes between two kinds of allocation requests.

Reference-counted requests
==========================

This means that the request comes for a domain and the :c:expr:`memflags`
of the request do not include :c:expr:`MEMF_no_refcount`.

In this case, the request is reference-counted to the domain's
total memory allocation, and the domain's claims can be used
to protect and redeem the allocation using claims.

For example, the allocation requests by :term:`domain builders` for the
:term:`guest physical memory` of domains are always reference-counted,
and as such, can be protected and redeemed by claims to the extent
the claims are applicable and sufficient for the allocation.

Not reference-counted requests
==============================

This means that the request is not for a domain, or the :c:type:`memflags`
of the request includes :c:macro:`MEMF_no_refcount`.

In this case, the request is not reference-counted to a domain's
memory allocation state, and as part of that, claims of a domain
cannot be used to protect and redeem the allocation using claims.

As such, the allocation request is not protected and redeemed by claims and
the allocator does not consider claims to check whether the request can
be satisfied, so the request can only be satisfied using unclaimed memory.

Therefore, such requests can only be satisfied using unclaimed memory.

Callers using MEMF_no_refcount
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Example callers which use :c:macro:`MEMF_no_refcount` when allocating memory
or use :c:macro:`MEMF_no_owner` which also sets :c:macro:`MEMF_no_refcount`
in the context of domains include:

- ``p2m_alloc_page()`` for allocating pages for the page-to-machine mapping.
- ``hap_set_allocation()`` for allocating memory for hardware-assisted paging.
- ``vmx_alloc_vlapic_mapping()`` for allocating the vLAPIC page for a HVM guest.
- ``vmtrace_alloc_buffer()`` for allocating the buffer for VM tracing.
- ``ioreq_server_alloc_mfn()`` for allocating memory for I/O requests.

Example actions happening at runtime on the request of running domains
which use :c:macro:`MEMF_no_refcount` or :c:macro:`MEMF_no_owner` to
bypass reference-counting include:

- ``memory_exchange()`` for exchanging memory pages of a domain.
- ``gnttab_transfer()`` for transferring pages between domains.

***********************
Claim protection checks
***********************

Unless the request is an exact-node request for a node-specific claim,
the allocator performs two protective checks to protect claimed memory
from being allocated to other domains while still allowing the claiming
domain to allocate it.

Before starting, the allocator takes the global :c:var:`heap_lock`.
This ensures that any previous changes to the state of the system's
unclaimed memory and the domain's total outstanding claims are complete
and visible, and no concurrent changes to those values can happen.

Protection of host-wide claims
=============================

The first check [1]_ the allocator performs is a check protecting host-wide claims
which are part of the total pool of the claims on the entire host.

1. Get the total amount of unclaimed memory available in the system.
   It is the sum of the free pages on all NUMA nodes (:c:var:`total_avail_pages`)
   minus the total amount of claimed memory across all domains
   (:c:var:`outstanding_claims`) this includes all host-wide claims
   and all node-specific claims.

2. Check whether the request can be satisfied by the unclaimed memory itself.

   If so, the allocation calls :c:func:`get_free_buddy()` to perform the
   node-specific checks and find free pages on the appropriate node(s)
   to satisfy the request.

   This is the common case, especially for smaller allocations and when the
   host is not under heavy memory pressure and not fully-claimed.

If the request cannot proceed based on the unclaimed memory, it is under
heavy memory pressure as the unclaimed memory is very low, which is where
the protection of claims becomes critical.

In these situations, the allocator needs to ensure that the domain has
enough claims to redeem the claimed memory to satisfy this request,
otherwise the request has to fail:

1. If the request is not for a domain or the request is disabling reference
   counting, the request fails.

2. If the total claims of the domain (:c:member:`domain.outstanding_claims`)
   cover the amount of claims needed to satisfy the request,
   the allocation can proceed further. Else, the request fails.

Protection of node-specific claims
==================================

This check protects claimed memory on the specific node from being allocated
without sufficient claims.

After passing the host-wide claims protection check, the allocator calls
:c:expr:`get_free_buddy()` to pick nodes for allocation and check the
node's suitability [2]_ for this request:

1. Get the number of unclaimed memory available on that node using the
   free pages on that NUMA node (``node_avail_pages[node]``) minus the
   total amount of claimed memory across all domains for that node
   (``node_outstanding_claims[node]``).

2. If the request can be satisfied by the sum of the unclaimed memory
   on that node and the claims of the domain for that node, the allocation
   can proceed on that node, else this node cannot satisfy this request.

3. If the allocation is an exact-node request, or the allocator
   has no further nodes to consider, the allocation fails.

4. Else, if the allocator has to consider further nodes for this request,
   the allocator continues to repeat the same process for the next node.

.. rubric:: Footnotes

.. [1] In principle, the host-wide check for the protection of host-wide claims
       could be skipped for node-exact requests that are reference-counted and
       covered by the claims of the domain for that node. The added code for
       This additional check would add complexity to the code, and as long as
       Xen must track global memory counters, those counters would still need
       to be accessed for all requests, so the added code could only delay the
       access to those global counters while adding more checks to all other
       requests. Therefore, that's not considered beneficial for now.

       However, if we want to replace the global :c:var:`heap_lock` serving
       as a global synchronisation point for all memory allocations with
       finer-grained (per-node) locks in the future, then this check could be
       added to allow more concurrency for node-exact allocations (and all
       free_page() calls) while still protecting claims, but that would be a
       future project, requiring significant changes to the code.

.. [2] If the request is reference-counted and the request is covered by
       the claims of the domain for that node, the request could proceed.
       But that would add complexity to the code, and as long as Xen must track
       per-node memory counters, those counters would still need to be updated
       for all allocations from this node, so the added code could only delay
       the access to those per-node counters while adding more checks to all
       other requests. Therefore, that's not considered beneficial for now.
