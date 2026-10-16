.. SPDX-License-Identifier: CC-BY-4.0

Redeeming
#########

.. contents:: Table of Contents
    :backlinks: entry
    :local:

After the buddy allocator returns pages for the allocation, the page allocator
redeems claims up to the allocation size in the same critical region that
updates the free-page counters.

For a ref-counted domain-heap allocation, the allocator redeems at most the
domain's outstanding total through the following steps. This prevents a
successful build allocation from leaving both the allocated pages and their
corresponding reservation charged against the installation-time allowance.
It does not replace the later page-assignment limit check.

Steps to redeem claims for an allocation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Redeem claims from :c:expr:`domain.claims[alloc_node]` on the allocation
   node, up to the size of that claim.
2. If the allocation exceeds that claim, redeem the remaining pages from the
   host-wide claims (:c:member:`domain.outstanding_pages` -
   :c:member:`domain.node_claims`), up to the size of the host-wide claim.
3. If the allocation exceeds the combination of those claims, redeem the
   remaining pages from other per-node claims rather than retaining a
   reservation for pages already allocated to the domain.

Relationship to the domain's max_pages limit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When setting claims, :c:func:`domain_set_claims()` checks that
:c:expr:`domain_tot_pages(domain) + domain.outstanding_pages`
fit within :c:member:`domain.max_pages`.

.. sidebar:: Locking

   See :ref:`designs/claims/accounting:Locking of the claims state`
   for the locks used to protect claims accounting state and invariants.

At memory allocation time, memory might be allocated on a node on which
the domain has not sufficient claims. To ensure that the allocation does
not unfairly exceed :c:member:`domain.max_pages` due to an allocation on
a node without sufficient claims, if they exist, host-wide claims of the
domain or its per-node claims must be redeemed.

To reliably check the domain's max_pages limit, the allocation would have
to take :c:member:`domain.page_alloc_lock` before taking :c:var:`heap_lock`
to lock the domain's limits and its current allocation for the duration
of the allocation.
This would ensure that the check against :c:member:`domain.max_pages` is
race-free, and could be considered for a later patch series.

Redemption precedes page assignment. If assignment fails, freeing the pages
does not restore the redeemed claim. For the existing claims model, it was
agreed among Xen maintainers that such a failure aborts the domain build,
releasing all allocated pages and the remaining claims as part of it.
