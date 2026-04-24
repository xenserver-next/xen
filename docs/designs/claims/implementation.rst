.. SPDX-License-Identifier: CC-BY-4.0

#####################
Claims Implementation
#####################

.. contents:: Table of Contents
    :backlinks: entry
    :local:

.. note:: This part describes implementation details of claims and their
    interaction with memory allocation in Xen. It covers the functions and
    data structures involved in :term:`installing claims`, allocating memory
    with :term:`claims`, and handling related edge cases.

Functions related to the implementation of claims and their interaction
with memory allocation.

**********************
Installation of claims
**********************

This section describes the functions and data structures involved
in :term:`installing claims` for domains and the internal functions for
validating and installing claim sets.

 .. c:function:: int domain_set_outstanding_pages(domain, pages)

    :param domain: The domain for which to set the outstanding claims
    :param pages:  The number of pages to claim floating for the domain
    :type domain:  struct domain *
    :type pages:   unsigned long
    :returns: 0 on success, or a negative error code on failure.

    Handles floating claim installation for :c:expr:`XENMEM_claim_pages`
    by setting the domain's :term:`floating claims` to the specified number of
    pages. It calculates the claims as the requested pages minus the domain's
    total pages. When :c:expr:`pages == 0`, it recalls all claims of the domain.

 .. c:function:: int domain_set_node_claims(domain, nr_claims, claims)

    :param domain: The domain for which to set the node claims
    :param nr_claims: The number of claims in the claim set
    :param claims: The claim set to install for the domain
    :type domain: struct domain *
    :type nr_claims: unsigned int
    :type claims: memory_claim_t *
    :returns: 0 on success, or a negative error code on failure.

    Handles :term:`installing claim sets`. It performs the validation
    of the :term:`claim set` and updates the domain's claims accordingly.

    The function works in four phases:

     1. Validate claim entries and validate node-specific claims availability
     2. Validate the floating request against the remaining availability
     3. Reset any current claims of the domain
     4. Install the claim set as the domain's claiming state

    Phase 1 checks claim entries for validity and memory availability:

     5. Target must be :c:expr:`XEN_DOMCTL_CLAIM_MEMORY_NODE_AGNOSTIC` or a node.
     6. Each target node may only appear once in the claim set.
     7. For node-specific claims, requested pages must not exceed the
        available memory on that node after accounting for existing claims.
     8. The explicit padding field must be zero for forward compatibility.

    Phase 2 checks:

     9. The total sum of the requested pages must not exceed the total unclaimed memory of the host after accounting for existing claims.
     10. The claims must not exceed the :c:expr:`domain.max_pages` limit.
         See :doc:`accounting` and :doc:`redeeming` for the accounting
         checks that enforce the domain's :c:expr:`domain.max_pages` limit.

************************************
Helper functions for managing claims
************************************

 .. function:: unsigned long domain_release_floating_claims(domain, release)

    :param domain: The domain for which to release floating claims
    :param release: The number of pages to release
    :type domain: struct domain *
    :type release: unsigned long
    :returns: The number of floating pages actually deducted from the domain.

    This function releases the specified number of floating claims.
    It limits the release to the number of floating claims actually held by
    the domain and updates the overall claim state accordingly.

 .. c:function:: unsigned long domain_release_node_claims(domain, node, release)

    :param domain: The domain for which to release the node claims
    :param node: The node for which to release the claim
    :param release: The number of pages to release from the claim
    :type domain: struct domain *
    :type node: nodeid_t
    :type release: unsigned long
    :returns: The number of pages actually deducted from the domain's claim.

    This function deducts a specified number of pages from a domain's
    claim on a specific node. It limits the release to the number of
    pages actually claimed by the domain on that node and updates the
    node-local claims currently held by the domain on that node,
    and it updates the floating and node-specific claim state accordingly.

 .. c:function:: void domain_recall_node_claims(struct domain *d)

    :param d: The domain for which to recall all node-specific claims.
    :type d: struct domain *

**********************
Allocation with claims
**********************

The functions below play a key role in allocating memory for domains.

 .. c:function:: int xc_domain_populate_physmap(xch, domid, extents, order, \
                                                mem_flags, extent_start)

    :param xch: The :term:`libxenctrl` interface
    :param domid: The ID of the domain
    :param extents: Number of extents
    :param order: Order of the extents
    :param mem_flags: Allocation flags
    :param extent_start: Starting PFN
    :type xch: xc_interface *
    :type domid: uint32_t
    :type extents: unsigned long
    :type order: unsigned int
    :type mem_flags: unsigned int
    :type extent_start: xen_pfn_t *
    :returns: 0 on success, or a negative error code on failure.

    This function is a wrapper for the ``XENMEM_populate_physmap`` hypercall,
    which is handled by the :c:expr:`populate_physmap()` function in the
    hypervisor. It is used by :term:`libxenguest` for populating the
    :term:`guest physical memory` of a domain. :term:`domain builders` can
    set the :term:`NUMA node affinity` and pass the preferred node to this
    function to steer allocations towards the preferred NUMA node(s) and let
    :term:`claims` ensure that the memory will be available even in cases
    of :term:`parallel domain builds` where multiple domains are being built
    at the same time.

The :term:`meminit` API calls :c:expr:`xc_domain_populate_physmap()`
for populating the :term:`guest physical memory`. It invokes the restartable
``XENMEM_populate_physmap`` hypercall implemented by
:c:expr:`populate_physmap()`.

.. c:function:: void populate_physmap(struct memop_args *a)

    :param a: Provides status and hypercall restart info
    :type a: struct memop_args *

    Allocates memory for building a domain and uses it for populating the
    :term:`physmap`. For allocation, it uses
    :c:expr:`alloc_domheap_pages()`, which forwards the request to
    :c:expr:`alloc_heap_pages()`.

    During domain creation, it adds the ``MEMF_no_scrub`` flag to the request
    for populating the :term:`physmap` to optimize domain startup by allowing
    the use of unscrubbed pages.

    When that happens, it scrubs the pages as needed using hypercall
    continuation to avoid long hypercall latency and watchdog timeouts.

    Domain builders can optimise on-demand scrubbing by running
    :term:`physmap` population pinned to the domain's NUMA node,
    keeping scrubbing local and avoiding cross-node traffic.

.. c:function:: struct page_info *alloc_heap_pages(unsigned int zone_lo, \
                                                   unsigned int zone_hi, \
                                                   unsigned int order, \
                                                   unsigned int memflags, \
                                                   struct domain *d)

    :param zone_lo: The lowest zone index to consider for allocation
    :param zone_hi: The highest zone index to consider for allocation
    :param order: The order of the pages to allocate (2^order pages)
    :param memflags: Memory allocation flags that may affect the allocation
    :param d: The domain for which to allocate memory or NULL
    :type zone_lo: unsigned int
    :type zone_hi: unsigned int
    :type order: unsigned int
    :type memflags: unsigned int
    :type d: struct domain *
    :returns: The allocated page_info structure, or NULL on failure

    This function allocates a contiguous block of pages from the heap.
    It checks claims and available memory before attempting the
    allocation. On success, it updates relevant counters and redeems
    claims as necessary.

    It first checks whether the request can be satisfied given the domain's
    claims and available memory using :c:expr:`claims_permit_request()`.
    If claims and availability permit the request, it calls
    :c:expr:`get_free_buddy()` to find a suitable block of free pages
    while respecting node and zone constraints.

    Simplified pseudocode of its logic:
.. code:: C

    struct page_info *alloc_heap_pages(unsigned int zone_lo,
                                       unsigned int zone_hi,
                                       unsigned int order,
                                       unsigned int memflags,
                                       struct domain *d) {
        /* D's claims and available memory need to permit the request. */
        if (!claims_permit_request(1UL << order, total_avail_pages, memflags,
                                   NUMA_NO_NODE, d,  outstanding_claims))
            return NULL;

        /* Find a suitable buddy block. Pass the zone range, order and
         * memflags so the helper can apply node and zone selection. */
        pg = get_free_buddy(zone_lo, zone_hi, order, memflags, d);
        if (!pg)
            return NULL;

        redeem_claims_for_allocation(d, 1UL << order, node_of(pg));
        update_counters_and_stats(d, order);
        if (pg_has_dirty_pages(pg))
            scrub_dirty_pages(pg);
        return pg;
    }

.. c:function:: struct page_info *get_free_buddy(zone_lo, zone_hi, order, \
                                                 memflags, domain)

    :param zone_lo: The lowest zone index to consider for allocation
    :param zone_hi: The highest zone index to consider for allocation
    :param order: The order of the pages to allocate (2^order pages)
    :param memflags: Flags for conducting the allocation
    :param domain: domain to allocate memory for or NULL
    :type zone_lo: unsigned int
    :type zone_hi: unsigned int
    :type order: unsigned int
    :type memflags: unsigned int
    :type domain: struct domain *
    :returns: The allocated page_info structure, or NULL on failure

    This function finds a suitable block of free pages in the buddy
    allocator while respecting claims and node-level available memory.

    Called by :c:expr:`alloc_heap_pages()` after verifying the request is
    permissible, it iterates over nodes and zones to find a buddy block
    that satisfies the request. It checks node-local claims before
    attempting allocation from a node.

    Using :c:expr:`claims_permit_request()`, it checks whether the node
    has enough unclaimed memory to satisfy the request or whether the
    domain's claims can permit the request on that node after accounting
    for outstanding claims.

    If the node can satisfy the request, it searches for a suitable block
    in the specified zones. If found, it returns the block; otherwise it
    tries the next node until all online nodes are exhausted.

    Simplified pseudo-code of its logic:
.. code:: C

    /*
     * preferred_node_or_next_node() represents the policy to first try the
     * preferred/requested node then fall back to other online nodes.
     */
    struct page_info *get_free_buddy(unsigned int zone_lo,
                                     unsigned int zone_hi,
                                     unsigned int order,
                                     unsigned int memflags,
                                     const struct domain *d) {
        nodeid_t request_node = MEMF_get_node(memflags);

        /*
         * Iterate over candidate nodes: start with preferred node (if any),
         * then try other online nodes according to the normal placement policy.
         */
        while (there are more nodes to try) {
            nodeid_t node = preferred_node_or_next_node(request_node);
            if (!node_allocatable_request(d, node_avail_pages[node],
                                          node_outstanding_claims[node],
                                          memflags, 1UL << order, node))
                goto try_next_node;

            /* Find a zone on this node with a suitable buddy */
            for (int zone = highest_zone; zone >= lowest_zone; zone--)
                for (int j = order; j <= MAX_ORDER; j++)
                    if ((pg = remove_head(&heap(node, zone, j))) != NULL)
                        return pg;
         try_next_node:
            if (request_node != NUMA_NO_NODE && (memflags & MEMF_exact_node))
                return NULL;
            /* Fall back to the next node and repeat. */
        }
        return NULL;
    }

*******************************************
Helper functions for allocation with claims
*******************************************

For allocating memory while respecting claims, :c:expr:`alloc_heap_pages()`
and :c:expr:`get_free_buddy()` use :c:expr:`claims_permit_request()` to
check whether the claims permit the request before attempting allocation.

If permitted, the allocation proceeds, and after success,
:c:expr:`redeem_claims_for_allocation()` redeems the claims for the allocation
based on the domain's claiming state and the node of the allocation.

See :ref:`designs/claims/design:Key design decisions` for the
rationale behind this design and the accounting checks that enforce
the :c:expr:`domain.max_pages` limit during allocation with claims.

.. c:function:: bool claims_permit_request(request, avail, claims, domain, \
                                           memflags, node)

    :param request: pages requested for allocation
    :param avail: total pages available or on node
    :param claims: total outstanding claims or on node
    :param domain: domain for which to check
    :param memflags: memory allocation flags for the request
    :param node: node of the request or NUMA_NO_NODE for a host-wide check
    :type request: unsigned long
    :type avail: unsigned long
    :type claims: unsigned long
    :type domain: const struct domain *
    :type memflags: unsigned int
    :type node: nodeid_t
    :returns: true if claims and available memory permit the request

    This function checks whether a memory allocation request can be
    satisfied given the current state of available memory and outstanding
    claims for the domain. It calculates the amount of unclaimed memory
    and determines whether it is sufficient to satisfy the request.

    If unclaimed memory is insufficient, it checks if the domain's claims
    can cover the shortfall, taking into account whether the request is
    node-specific or floating.

.. c:function:: void redeem_claims_for_allocation(domain, allocation, \
                                                  alloc_node)

    :param domain: The domain for which to redeem claims
    :param allocation: The number of pages allocated
    :param alloc_node: The node on which the allocation was made
    :type domain: struct domain *
    :type allocation: unsigned long
    :type alloc_node: nodeid_t

    See :doc:`redeeming` for details on redeeming claims after allocation.

**************************************
Offlining memory in presence of claims
**************************************

When offlining pages, Xen must ensure that available memory on a node
and the total number of free pages does not fall below their respective outstanding claims. If it does, Xen recalls
claims from domains until accounting is valid again.

This is triggered by privileged domains via the
``XEN_SYSCTL_page_offline_op`` sysctl or by machine-check memory errors.

Offlining currently allocated pages cannot remove those in-use pages from
circulation. They are marked for offlining and are offlined when freed back
to the allocator. However, when already free pages are directly offlined,
free memory the outstanding claims may need to be adjusted directly too.

:c:expr:`reserve_offlined_page()` need to check whether offlining the page
reduces :c:expr:`total_avail_pages` fall below :c:expr:`outstanding_claims` or
:c:expr:`node_avail_pages[page->node]` fall below
:c:expr:`node_outstanding_claims[page->node]`. If so,
:c:expr:`reserve_offlined_page()` must look for domains with relevant claims
and recall those claims until the claim accounting is valid again.

- When
  :c:expr:`node_outstanding_claims[offline_node]` exceeds
  :c:expr:`node_avail_pages[offline_node]` for the node of the offlined page,
  :c:expr:`reserve_offlined_page()` calls :c:expr:`domain_release_node_claims()`
  to recall claims on that node from domains with claims on the node of the
  offlined buddy until the claim accounting of the node is valid again.

- When total :c:expr:`outstanding_claims` exceeds :c:expr:`total_avail_pages`,
  :c:expr:`reserve_offlined_page()` calls
  :c:expr:`domain_release_floating_claims()` to recall floating claims
  from domains until the overall claims accounting is valid again.

This can violate claim guarantees, but it is necessary to maintain system
stability when memory must be offlined.

.. c:function:: int reserve_offlined_page(struct page_info *head)

    :param head: The page being offlined
    :type head: struct page_info *
    :returns: 0 on success, or a negative error code on failure.

    This function is called during the offlining process to offline pages.

    If offlining a page causes available memory to fall below outstanding
    claims, it checks the node-specific and floating claim accounting
    and recalls claims from domains as necessary to ensure accounting
    invariants hold after a buddy is offlined.
