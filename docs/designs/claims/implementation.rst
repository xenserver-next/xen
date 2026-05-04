.. SPDX-License-Identifier: CC-BY-4.0

Implementation
##############

.. contents:: Table of Contents
    :backlinks: entry
    :local:

.. note:: This part describes implementation details of claims and their
    interaction with memory allocation in Xen. It covers the functions and
    data structures involved in :term:`installing claims` and allocating memory
    with :term:`claims`.

Functions related to the implementation of claims and their interaction
with memory allocation.

**********************
Installation of claims
**********************

This section describes the functions and data structures involved in
:term:`installing claims` for domains, and the internal functions for
validating and installing claim sets.

 .. c:function:: int domain_set_outstanding_pages(domain, pages)

    This function is replaced by :c:func:`domain_set_claim_entries()`.

    .. version-removed:: claims-v7

 .. c:function:: int domain_set_claim_entries(domain, nr_entries, claim_set)

    :param domain: The domain for which to set the node claims
    :param nr_entries: The number of claims in the claim set
    :param claim_set: The claim set to install for the domain
    :type domain: struct domain *
    :type nr_entries: unsigned int
    :type claim_set: memory_claim_t *
    :returns: 0 on success, or a negative error code on failure.

    Handles :term:`installing claim sets`. It performs validation of the
    :term:`claim set` and updates the domain's claims accordingly.

    The function works in four phases:

     1. Validate claim entries and check node-specific claims availability
     2. Validate the unpinned request against the remaining availability
     3. Reset any current claims of the domain
     4. Install the claim set as the domain's claiming state

    Phase 1 checks claim entries for validity and memory availability:

     5. Target must be :c:macro:`XEN_DOMCTL_CLAIM_MEMORY_TOTAL` or a node.
     6. Each target node may only appear once in the claim set.
     7. For node-specific claims, requested pages must not exceed the
        available memory on that node after accounting for existing claims.
     8. The explicit padding field must be zero for forward compatibility.

    Phase 2 checks:

     9. The total sum of the requested pages must not exceed the total unclaimed memory of the host after accounting for existing claims.
     10. The claims must not exceed the :c:member:`domain.max_pages` limit.
         See :doc:`accounting` and :doc:`redeeming` for the accounting
         checks that enforce the domain's :c:member:`domain.max_pages` limit.

    .. versionadded:: claims-v5

 .. c:function:: int domain_get_claim_entries(domain, nr_entries, claim_set)

    :param domain: The domain for which to retrieve a claim set
    :param nr_entries: The number of claims in the claim set
    :param claim_set: The preallocated buffer for up to nr_entries claim entries
    :type domain: struct domain *
    :type nr_entries: unsigned int *
    :type claim_set: memory_claim_t *
    :returns: 0 on success with nr_entries updated to the number of claims
              written to the buffer, or a negative error code on failure.

    Retrieves a claim set for the current claims of the domain and writes
    it to the provided buffer. The number of claims written to the buffer
    is stored in the variable pointed to by ``nr_entries``.

    ``nr_entries`` specifies the size of the provided buffer for claim
    entries, and the function writes up to that many claim entries to
    the buffer. If the buffer is too small to hold all claim entries,
    the function returns -:c:macro:`ERANGE` and updates ``nr_entries``
    to the number of entries needed to hold all claim entries.

 .. versionadded:: claims-v7

************************************
Helper functions for managing claims
************************************

 .. c:function:: unsigned long domain_release_host_claims(domain, release)

    :param domain: The domain for which to release unpinned claims
    :param release: The number of pages to release
    :type domain: struct domain *
    :type release: unsigned long
    :returns: The number of unpinned pages actually deducted from the domain.

    This function releases the specified number of unpinned claims.
    It limits the release to the number of unpinned claims actually held by
    the domain and updates the overall claim state accordingly.

    .. versionadded:: claims-v4

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
    and it updates the unpinned and node-specific claim state accordingly.

    .. versionadded:: claims-v5

 .. c:function:: void domain_recall_node_claims(domain, recall)

    :param domain: The domain for which to recall node claims
    :param recall: The number of node-specific pages to recall
    :type domain: struct domain *
    :type recall: unsigned long

    This function recalls the specified number of node-specific claims
    from the domain and updates the overall claim state accordingly.

    It iterates over the domain's node-specific claims, calls
    :c:func:`domain_release_node_claims()` to up to the given pages from
    the node claims until the specified number of pages has been recalled,
    or all node-specific claims have been exhausted.

    This function is used to recall node-specific claims from a domain when
    offlining memory or when pages for a domain are allocated on other
    nodes than the claimed node.

    .. versionadded:: claims-v5

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
    which is handled by the :c:func:`populate_physmap()` function in the
    hypervisor. It is used by :term:`libxenguest` for populating the
    :term:`guest physical memory` of a domain. :term:`domain builders` can
    set the :term:`NUMA node affinity` and pass the preferred node to this
    function to steer allocations towards the preferred NUMA node(s) and let
    :term:`claims` ensure that the memory will be available even in cases
    of :term:`parallel domain builds` where multiple domains are being built
    at the same time.

The :term:`meminit` API calls :c:func:`xc_domain_populate_physmap()`
for populating the :term:`guest physical memory`. It invokes the restartable
``XENMEM_populate_physmap`` hypercall implemented by
:c:func:`populate_physmap()`.

.. c:function:: void populate_physmap(struct memop_args *a)

    :param a: Provides status and hypercall restart info
    :type a: struct memop_args *

    Allocates memory for building a domain and uses it for populating the
    :term:`physmap`. For allocation, it uses
    :c:func:`alloc_domheap_pages()`, which forwards the request to
    :c:func:`alloc_heap_pages()`.

    During domain creation, it adds the :c:macro:`MEMF_no_scrub` flag to the request
    for populating the :term:`physmap` to optimise domain startup by allowing
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
    claims and available memory using :c:func:`claims_permit_request()`.
    If claims and availability permit the request, it calls
    :c:func:`get_free_buddy()` to find a suitable block of free pages
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

    Called by :c:func:`alloc_heap_pages()` after verifying the request is
    permissible, it iterates over nodes and zones to find a buddy block
    that satisfies the request. It checks node-local claims before
    attempting allocation from a node.

    Using :c:func:`claims_permit_request()`, it checks whether the node
    has enough unclaimed memory to satisfy the request or whether the
    domain's claims can permit the request on that node after accounting
    for outstanding claims.

    If the node can satisfy the request, it searches for a suitable block
    in the specified zones. If found, it returns the block; otherwise it
    tries the next node until all online nodes are exhausted.

    Simplified pseudocode of its logic:

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
            unsigned long avail_pages = node_avail_pages[node] -
                                        node_outstanding_claims[node]
                                        + ((d && !(memflags & MEMF_no_refcount))
                                           ? d->claims[node] : 0);

            /* Ensure the target node and the claims permit can this allocation */
            if ( avail_pages < (1UL << order) )
                goto next_node;

            /* Find a zone on this node with a suitable buddy */
            for (int zone = highest_zone; zone >= lowest_zone; zone--)
                for (int j = order; j <= MAX_ORDER; j++)
                    if ((pg = remove_head(&heap(node, zone, j))) != NULL)
                        return pg;
         next_node:
            if (request_node != NUMA_NO_NODE && (memflags & MEMF_exact_node))
                return NULL;
            /* Fall back to the next node and repeat. */
        }
        return NULL;
    }

.. note:: The actual implementation includes additional details
   but the pseudocode captures the core logic of checking claims
   and available memory while searching for a suitable buddy.

**************************************
Offlining memory in presence of claims
**************************************

When offlining pages, Xen must ensure that available memory on a node
and the total number of free pages does not fall below their respective
outstanding claims. If it does, Xen recalls claims from domains until
accounting is valid again.

This is triggered by privileged domains via the
``XEN_SYSCTL_page_offline_op`` sysctl or by machine-check memory errors.

Offlining currently allocated pages cannot remove those in-use pages from
circulation. They are marked for offlining and are offlined when freed back
to the allocator. However, when already free pages are directly offlined,
free memory the outstanding claims may need to be adjusted directly too.

:c:func:`reserve_offlined_page()` needs to check whether offlining the page
causes :c:var:`total_avail_pages` to fall below :c:var:`outstanding_claims` or
:c:expr:`node_avail_pages[page->node]` to fall below
:c:expr:`node_outstanding_claims[page->node]`. If so,
:c:func:`reserve_offlined_page()` must look for domains with relevant claims
and recall those claims until the claim accounting is valid again.

- When
  :c:expr:`node_outstanding_claims[page->node]` exceeds
  :c:expr:`node_avail_pages[page->node]` for the offlined page,
  :c:func:`reserve_offlined_page()` should call
  :c:func:`domain_release_node_claims()`
  to recall claims on that node from domains with claims on the node of the
  offlined buddy until the claim accounting of the node is valid again.

- When total :c:var:`outstanding_claims` exceeds :c:var:`total_avail_pages`,
  :c:func:`reserve_offlined_page()` calls
  :c:func:`domain_release_host_claims()` to recall unpinned claims
  from domains until the overall claims accounting is valid again.

This can violate claim guarantees, but it is necessary to maintain system
stability when memory must be offlined.

.. c:function:: int reserve_offlined_page(struct page_info *head)

    :param head: The page being offlined
    :type head: struct page_info *
    :returns: 0 on success, or a negative error code on failure.

    This function is called during the offlining process to offline pages.

    If offlining a page causes available memory to fall below outstanding
    claims, it checks the node-specific and unpinned claim accounting
    and recalls claims from domains as necessary to ensure accounting
    invariants hold after a buddy is offlined.
