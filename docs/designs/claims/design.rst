.. SPDX-License-Identifier: CC-BY-4.0

#############
Claims Design
#############

.. contents:: Table of Contents
    :backlinks: entry
    :local:

************
Introduction
************

Xen's page allocator supports a :term:`claims` API that allows privileged
:term:`domain builders` to reserve an amount of available memory before
:term:`populating` the :term:`guest physical memory` of new :term:`domains`
they are creating, configuring and building.

These reservations are called :term:`claims`. They ensure that the claimed
memory remains available for the :term:`domains` when allocating it, even
if other :term:`domains` are allocating memory at the same time.

:term:`Installing claims` is a privileged operation performed by
:term:`domain builders` before they populate the :term:`guest physical memory`.
This prevents other :term:`domains` from allocating memory earmarked
for :term:`domains` under construction. Xen maintains the per-domain
claim state for pages that are claimed but not yet allocated.

When claim installation succeeds, Xen updates the claim state to reflect
the new targets and protects the claimed memory until it is allocated or
the claim is released. As Xen allocates pages for the domain, claims are
redeemed by reducing the claim state by the size of each allocation.

************
Design Goals
************

The design's primary goals are:

1. Allow :term:`domain builders` to claim memory
   on multiple :term:`NUMA nodes` using a :term:`claim set` atomically.

2. Preserve the existing :c:expr:`XENMEM_claim_pages` hypercall command
   for compatibility with existing :term:`domain builders` and its legacy
   semantics, while introducing a new, unrestricted hypercall command for
   new use cases such as NUMA-aware claim sets.

3. Unbound claims are supported for compatibility with existing
   :term:`domain builders` and for use cases where a flexible claim that
   can be satisfied from any node is desirable, such as on UMA machines or
   as a fallback for memory that comes available on any node.

   This means we cannot remove or replace the legacy
   floating claim call nor the needed variables maintaining the floating
   claim state. They are still very much needed: claims are not just for NUMA use
   cases, but for :term:`parallel domain builds` in general.

   Only on UMA machines is a floating claim the same as a claim on node 0,
   but the same is not true for NUMA machines, where floating claims can claim
   more memory than any single node, and the floating claim can be used as a
   flexible fallback for claiming memory on any node, which can be useful
   when preferred NUMA node(s) should be claimed, but may have insufficient
   free memory at the time of claim installation, and the floating claim can
   ensure that the shortfall is available from any node.

4. Use fast allocation-time claims protection in the allocator's hot paths
   to protect claimed memory from parallel allocations from other domain
   builders in case of parallel domain builds, and to protect claimed
   memory from allocations from already running domains.

***************
Design Overview
***************

The legacy :ref:`XENMEM_claim_pages` hypercall is superseded by
:c:expr:`XEN_DOMCTL_claim_memory`. This hypercall installs a :term:`claim set`.
It is an array of :c:expr:`memory_claim_t` entries, where each entry specifies
a page count and a target: either a specific NUMA node ID or a selector.

Like legacy claims, claim sets are validated and installed under
:c:expr:`domain.page_alloc_lock` and :c:expr:`heap_lock`: Either the entire
set is accepted, or the request fails with no side effects.  Repeated calls
to install claims replace any existing claims for the domain rather than
accumulating.

As installing claim sets after allocations is not a supported use case,
the legacy behaviour of subtracting existing allocations from installed
claims is somewhat surprising and counterintuitive, and page exchanges
make incremental per-node tracking of already-allocated pages on a per-node
basis difficult. Therefore, claim sets do not retain the legacy behaviour of
subtracting existing allocations, optionally on a per-node basis, from the
installed claims across the individual claim set entries.

Summary:

- Legacy domain builders can continue to use the previous (now deprecated)
  :c:expr:`XENMEM_claim_pages` hypercall command to install single-node claims
  with the legacy semantics and, aside from improvements or fixes to floating
  claims in general, observe no changes in their behaviour.

- Updated domain builders can take advantage of claim sets to install
  NUMA-aware :term:`claims` on multiple :term:`NUMA nodes` and/or claims
  that are not bound to specific nodes. It has more intuitive semantics
  that do not subtract existing allocations from the installed claims.
  Such semantics are also simpler to understand and maintain, and they
  are not affected by the complexity of tracking existing allocations
  on a per-node basis across page exchanges happening concurrently
  with claim installation for new domains under construction.

For readers following the design in order, the next sections cover the
following topics:

1. :doc:`/designs/claims/installation` explains how claim sets are installed.
2. :doc:`/designs/claims/protection` describes how claimed memory is
   protected during allocation.
3. :doc:`/designs/claims/redeeming` explains how claims are redeemed as
   allocations succeed.
4. :doc:`/designs/claims/accounting` describes the accounting model that
   underpins those steps.

********************
Key design decisions
********************

.. glossary::

 :c:expr:`node_outstanding_claims[MAX_NUMNODES]`
  Tracks the sum of all claims on a node. :c:expr:`get_free_buddy()` checks
  it before scanning zones on a node, so claimed memory is protected from
  other allocations.

 :c:expr:`redeem_claims_for_allocation()`
   When allocating memory for a domain, the page allocator redeems the
   matching claims for this allocation, ensuring the domain's total memory
   allocation as :c:expr:`domain_tot_pages(domain)` plus its outstanding claims
   as :c:expr:`domain.floating_claims + domain.node_claims` remain within the
   domain's limits, defined by :c:expr:`domain.max_pages`.
   See :doc:`redeeming` for details on redeeming claims.

 :c:expr:`domain.floating_claims` (formerly :c:expr:`domain.outstanding_claims`)
  Support for :term:`floating claims` is maintained for two reasons: first,
  for compatibility with existing domain builders, and second, for use cases
  where a flexible claim that can be satisfied from any node is desirable.

  When the preferred NUMA node(s) for a domain do not have sufficient free
  memory to satisfy the domain's memory requirements, floating claims provide
  a flexible fallback for the memory shortfall from the preferred node(s) that
  can be satisfied from any available node.

  In this case, :term:`domain builders` can use a combination of passing
  the preferred node to :c:expr:`xc_domain_populate_physmap()` and
  :term:`NUMA node affinity` to steer allocations towards the preferred
  NUMA node(s), while letting floating claims ensure that the shortfall
  is available.

  This allows the domain builder to define a set of desired NUMA nodes to
  allocate from and even specify which nodes to prefer for an allocation,
  but the claim for the shortfall is flexible, not specific to any node.

*********
Non-goals
*********

Using per-node allocator data
=============================

Some data structures could be moved into the per-node allocator data
allocated by `init_node_heap()` to avoid bouncing those data structures
between nodes. Those can be moved to the per-node allocator data in the
future, but that is not a priority. While that would reduce this bouncing,
it would not eliminate the need to take the global :c:expr:`heap_lock`,
which is still needed to protect the allocator's state during allocation
and freeing of pages.

The synchronisation point for taking the global :c:expr:`heap_lock` is
the main point of contention during allocation, freeing and scrubbing
pages. The overhead of accessing the per-node claims accounting data
is expected to be minimal.

Avoiding the :c:expr:`heap_lock` would be difficult to achieve as it
would require updating the page allocator to maintain atomic updates
of a new `total_unclaimed_pages` counter, which would be decremented
on allocation and claims installation and incremented on freeing of
pages and claims, and to check that counter in the hot path of the
allocator to protect claimed memory from other allocations.

However, we aim move that data into the per-node allocator data in the
future to reduce the need to bounce those data structures between nodes.

Legacy behaviours
=================

Installing claims is a privileged operation performed by domain builders
before they populate guest memory. As such, tracking previous allocations
is not in scope for claims.

For the following reasons, claim sets do not retain the legacy behaviour
of subtracting existing allocations from installed claims:

- Xen does not currently maintain a ``d->node_tot_pages[node]`` count,
  and the hypercall to exchange extents of memory with new memory makes
  such accounting relatively complicated.

- The legacy behaviour is somewhat surprising and counterintuitive.
  Because installing claims after allocations is not a supported use case,
  subtracting existing allocations at installation time is unnecessary.

- Claim sets are a new API and can provide more intuitive semantics
  without subtracting existing allocations from installed claims. This
  also simplifies the implementation and makes it easier to maintain.

Versioned hypercall
===================

The :term:`domain builders` using the :c:expr:`XEN_DOMCTL_claim_memory`
hypercall also need to use other version-controlled hypercalls which
are wrapped through the :term:`libxenctrl` library.

Wrapping this call in :term:`libxenctrl` is therefore a practical approach;
otherwise, we would have a mix of version-controlled and unversioned hypercalls,
which could be confusing for API users and for future maintenance. From the
domain builders' viewpoint, it is more consistent to expose the claims
hypercall in the same way as the other calls they use.

Stable interfaces also have drawbacks: with stable syscalls, Linux needs
to maintain the old interface indefinitely, which can be a maintenance burden
and can limit the ability to make improvements or changes to the interface
in the future. Linux carries many system call successor families, e.g., oldstat,
stat, newstat, stat64, fstatat, statx, with similar examples including openat,
openat2, clone3, dup3, waitid, mmap2, epoll_create1, pselect6 and many more.
Glibc hides that complexity from users by providing a consistent API, but it
still needs to maintain the old system calls for compatibility.

In contrast, versioned hypercalls allow for more flexibility and evolution of
the API while still providing a clear path to adopt new features. The reserved
fields and reserved bits in the structures of this hypercall allow for many
future extensions without breaking existing callers.
