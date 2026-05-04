.. SPDX-License-Identifier: CC-BY-4.0

Redeeming
#########

.. contents:: Table of Contents
    :backlinks: entry
    :local:

After the buddy allocator returned the pages for the allocation,
:c:func:`redeem_claims_for_allocation()` redeems claims up to the size of
the allocation in the same critical region that updates the free-page counters.

The function performs the following steps to redeem the matching
claims for this allocation. It ensures that the domain's total memory
allocation as :c:func:`domain_tot_pages` plus its outstanding
claims as :c:member:`domain.outstanding_pages` remain within the
domain's limits, defined by :c:member:`domain.max_pages`:

Steps to redeem claims for an allocation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Step 1:
  Redeem claims from :c:expr:`domain.claims[alloc_node]` on the allocation
  node, up to the size of that claim.
Step 2:
  If the allocation exceeds :c:expr:`domain.claims[alloc_node]`, redeem the
  remaining pages from the unpinned claims
  (:c:member:`domain.outstanding_pages` - :c:member:`domain.node_claims`),
  up to the size of the unpinned claims.
Step 3:
  If the allocation exceeds the combination of those claims, redeem the
  remaining pages from other per-node claims so that the domain's total
  allocation plus claims remain within the domain's :c:member:`domain.max_pages`
  limit.

Enforcing the domain's max_pages limit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:c:func:`domain_tot_pages` + :c:member:`domain.outstanding_pages`
must not exceed the :c:member:`domain.max_pages` limit, otherwise
the domain could exceed its memory entitlement.

At claim installation time, :c:func:`domain_install_claim_set()` performs
this check.

.. :sidebar::
   See :ref:`designs/claims/accounting:Locking of claims accounting`
   for the locks used to protect claims accounting state and invariants.

At memory allocation time
  If (unexpectedly) a domain builder ends up allocating memory from
  different nodes than it claimed from, the domain's total allocation
  plus claims could exceed the domain's :c:member:`domain.max_pages`
  limit, unless the page allocator redeems claims from other nodes
  to ensure the sum of the domain's claims and populated pages
  remains within the :c:member:`domain.max_pages` limit.

  :c:func:`redeem_claims_for_allocation()`
  cannot reliably check :c:member:`domain.max_pages` race-free because
  :c:member:`domain.max_pages` is not protected by the :c:var:`heap_lock`
  taken by the page allocator during allocation.

  To check the domain's limits, it would have to take the
  :c:member:`domain.page_alloc_lock` to inspect the domain's
  limits and its current allocation. However, taking that lock
  while holding the :c:var:`heap_lock` would invert the locking
  order and could lead to deadlocks.

  Therefore, :c:func:`redeem_claims_for_allocation()`
  redeems the remaining allocation from other-node claims in Step 3.
