.. SPDX-License-Identifier: CC-BY-4.0

#####################
Claims Implementation
#####################

.. contents::
    :backlinks: entry
    :local:

.. note:: This part describes the implementation details of claims and their
    interaction with memory allocation in Xen. It covers the functions and
    data structures involved in installing claims, allocating memory with
    claims, and handling edge cases related to claims.

Functions related to the implementation of claims and their interaction with
memory allocation.

**********************
Installation of claims
**********************

Installation of legacy claims and claim sets for domains is performed through
the ``xenmem`` hypercall command ``XENMEM_claim_pages`` and the ``domctl``
hypercall command ``XEN_DOMCTL_claim_memory``, which are implemented in the
functions ``domain_set_outstanding_pages()`` and ``domain_set_node_claims()``.

See:

- :ref:`XENMEM_claim_pages` for details on the legacy claim installation path
- :ref:`XEN_DOMCTL_claim_memory` for details on the claim set installation path

domain_set_outstanding_pages()
------------------------------

```domain_set_outstanding_pages()`` is the main entry point for installing
claims for a domain. It and its helper functions perform the necessary checks
and updates to install the claims for a domain. For installing claim sets,
it takes care of locking the necessary locks and forwards the claim set
to the internal function ``domain_set_node_claims()`` for further processing.

.. c:function:: int domain_set_outstanding_pages(struct domain *d, \
                                                 unsigned int nr_claims, \
                                                 memory_claim_t *claims)

    :param d: The domain for which to set the outstanding claims
    :param nr_claims: The number of claims in the claim set
    :param claims: The claim set to install for the domain
    :type claims: memory_claim_t *
    :type d: struct domain *
    :type nr_claims: unsigned int
    :returns: 0 on success, or a negative error code on failure.

    This function is the core of the claims installation logic, which performs
    the necessary checks and updates to set the outstanding claims for a domain
    based on the provided claim set. It ensures that the new claims are valid
    and do not exceed the system's available memory, and it updates the
    domain's claiming state accordingly.

    For installing claim sets, it takes care of locking the necessary locks
    to ensure thread safety during the update of the domain's claiming
    state and forwards the claim set to the internal function
    ``domain_set_node_claims()`` for claim sets validation and installation.

    It is largely unchanged from the traditional claim installation path except
    for passing the claim set to ``domain_set_node_claims()`` and releasing
    also claims on nodes when resetting all claims for a domain.

domain_set_node_claims()
------------------------

``domain_set_node_claims()`` is the internal function to handle installing
claim sets for a domain. It performs the full validation of the claim set
and updates the domain's node claims accordingly if the claim set is valid.

It is called by ``domain_set_outstanding_pages()`` after acquiring the
necessary locks for installing claim sets.

.. c:function:: int domain_set_node_claims(struct domain *d, \
                                           unsigned int nr_claims, \
                                           memory_claim_t *claims)

    :param d: The domain for which to set the node claims
    :param nr_claims: The number of claims in the claim set
    :param claims: The claim set to install for the domain
    :type claims: memory_claim_t *
    :type d: struct domain *
    :type nr_claims: unsigned int
    :returns: 0 on success, or a negative error code on failure.

    This function validates the provided claim set and, if valid, updates the
    domain's node claims accordingly. It performs full input validation and
    ensures that the claims do not exceed the domain's maximum page limits.
    If the claims are valid but cannot be satisfied due to insufficient memory,
    it returns an appropriate error code.

    It works in four phases:

    1. Validating the claim entries and checking for node-local availability
    2. Validating the total claims and checking global memory availability
    3. Resetting any current claims of the domain
    4. Installing the claim set as the domain's claiming state

    Phase 1 performs the following checks for each claim set entry:

    1. Target must be ``XEN_DOMCTL_CLAIM_MEMORY_GLOBAL`` or an online node
    2. Each target node can only have one claim entry in the claim set
    3. For node-local claims, the requested pages must not exceed the available
       memory on that node after accounting for existing claims.
    4. The explicit padding field must be zero for forward compatibility.

    Phase 2 performs the following checks:

    1. The sum of ``domain_tot_pages(d)``, global and node-local claims must
       not exceed the domain's maximum page limits.
    2. The sum of claims must not exceed the globally available memory.

    See :doc:`accounting` for details on the claims accounting state and
    invariants.

************************************
Helper functions for managing claims
************************************

``release_node_claim()`` and ``release_global_claims()`` are helper functions
used by the following functions to release claims from domains when necessary:

- By :ref:`designs/claims/implementation:consume_allocation()` for
  consuming claims after an allocation.
- By :ref:`designs/claims/implementation:unset_node_claims()` for
  resetting claims when resetting the claiming state.
- By :ref:`designs/claims/implementation:reserve_offlined_page()` for
  recalling claims when offlining pages reduces the available memory below the
  currently claimed pages.

release_node_claim()
--------------------

.. c:function:: unsigned long release_node_claim(struct domain *d, \
                                                 nodeid_t node, \
                                                 unsigned long release)

    :param d: The domain for which to release the node claim
    :param node: The node for which to release the claim
    :param release: The number of pages to release from the claim
    :type d: struct domain *
    :type node: nodeid_t
    :type release: unsigned long
    :returns: The number of pages actually released from the claim

    This function releases a specified number of pages from a domain's claim
    on a specific node. It limits the release to the amount of claims currently
    held by the domain on that node, and it updates the global and node-level
    outstanding claims accordingly.

    It is used by unset_node_claims() to release all claims for a domain when
    resetting its claiming state and during the claim consumption process to
    release claims as they are consumed by allocations.

release_global_claims()
-----------------------

.. c:function:: unsigned long release_global_claims(struct domain *d, \
                              unsigned long release)

    :param d: The domain for which to release the global claim
    :param release: The number of pages to release
    :type d: struct domain *
    :type release: unsigned long
    :returns: The number of pages actually released from the global claim.

    This function releases a specified number of pages from a domain's global
    claim. It limits the release to the amount of global claims currently held
    by the domain, and it updates the global outstanding claims accordingly.

    It is used by domain_set_outstanding_pages() to release all global claims
    for a domain when resetting its claiming state and when allocating memory
    for a domain with a claim present to release global claims.

unset_node_claims()
-------------------

.. c:function:: void unset_node_claims(struct domain *d)

    :param d: The domain for which to unset the node claims.
    :type d: struct domain *

    This function releases all outstanding node claims for the specified domain.
    It iterates over all online nodes and releases the claims for each node,
    ensuring that the domain's claiming state is reset properly.

    It is used when resetting all claims for a domain, and is used by
    ``domain_set_outstanding_pages()`` when the new claim is zero to reset
    the domain's claiming state and release all claims for the domain.

**********************
Allocation with claims
**********************

Domain builders and Xen itself can allocate memory for a domain with claims.

populate_physmap()
------------------

The main allocation path for domain builders are ``libxenguest``'s
``meminit_hvm()`` and ``meminit_pv()`` functions, which call
``xc_domain_populate_physmap()`` to populate the guest's memory, which in turn
calls the ``xenmem`` hypercall command ``XENMEM_populate_physmap``.

This command is implemented in the function ``populate_physmap()``:

.. c:function:: void populate_physmap(struct memop_args *a)

    :param a: The arguments for the populate_physmap operation
    :type a: struct memop_args *

    This function implements the logic for the ``XENMEM_populate_physmap``
    hypercall command, which is used by domain builders to allocate memory for
    a domain. When the domain creation has not finished yet, this function
    adds the ``MEMF_no_scrub`` flag to the allocation request to allow the
    buddy allocator to return unscrubbed pages, and if the allocator does so,
    it scrubs them before adding them to the domain's memory and returning.

    Toolstacks might want to run the ``libxenguest``'s ``meminit_hvm()`` and
    ``meminit_pv()`` functions on a CPU that is pinned on a CPU of the target
    NUMA node to scrub the pages from that node without cross-node traffic
    for efficient scrubbing during domain build.

    For allocation, it uses ``alloc_domheap_pages()`` which in turn forwards
    the request to ``alloc_heap_pages()``.

alloc_heap_pages()
------------------

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

    This function is responsible for allocating a contiguous block of pages
    from the heap. It performs checks against claims and available memory
    before attempting the allocation. If the allocation is successful,
    it updates the relevant counters and consumes claims as necessary.

    It first checks if the request can be satisfied given the domain's claims
    and the available memory by using the claims_permit_request() function.

    If it was allowed to return also unscrubbed pages using ``MEMF_no_scrub``,
    it may return also unscrubbed pages.

    This is also the case when called by a domain builder when populating
    a domain during its creation phase where ``populate_physmap()`` adds
    the ``MEMF_no_scrub`` flag to allow ``alloc_heap_pages()`` to return
    unscrubbed pages, and ``populate_physmap()`` then scrubs them using
    hypercall continuation to avoid longer scrubbing periods which could
    otherwise cause long hypercall latency and even Xen watchdog timeouts.

    Simplified pseudo-code of its logic:
.. code:: C

    struct page_info *alloc_heap_pages(d, order, memflags) {
        if (!claims_permit_request(d, memflags, 1 << order, NUMA_NO_NODE))
            return NULL;
        pg = get_free_buddy(order, memflags, d);
            return NULL;
        consume_allocation(d, 1 << order, node_of(pg));
        update_counters_and_stats(d, order);
        if (pg has dirty pages)
            scrub_dirty_pages(pg);
        return pg;
    }

get_free_buddy()
----------------

.. c:function:: struct page_info *get_free_buddy(unsigned int zone_lo, \
                                        unsigned int zone_hi, \
                                        unsigned int order, \
                                        unsigned int memflags, \
                                        const struct domain *d)

    :param zone_lo: The lowest zone index to consider for allocation
    :param zone_hi: The highest zone index to consider for allocation
    :param order: The order of the pages to allocate (2^order pages)
    :param memflags: Flags for conducting the allocation
    :param d: domain to allocate memory for or NULL
    :type zone_lo: unsigned int
    :type zone_hi: unsigned int
    :type order: unsigned int
    :type memflags: unsigned int
    :type d: struct domain *
    :returns: The allocated page_info structure, or NULL on failure

    This function is responsible for finding a suitable block of free pages
    in the buddy allocator while respecting the claims and available memory
    constraints on the nodes.

    It is called by alloc_heap_pages() after verifying that the request is
    permissible given on the level of globally available memory and claims.

    It iterates over the nodes and zones to find a block of pages (a buddy)
    that can satisfy the request, and it checks the node-local claims before
    attempting to allocate from a node.

    Using the claims_permit_request() function, it checks if the node has
    enough unclaimed memory to satisfy the request, or if the domain's claims
    can permit the request on that node after accounting for the node's
    available memory and outstanding claims.

    If the node can satisfy the request, it looks for a suitable block of free
    pages in the specified zones on that node. If it finds a block, it returns
    it. If it cannot find a block on that node, it tries the next node until
    it has tried all online nodes.

    Simplified pseudo-code of its logic:
.. code:: C

    struct page_info *get_free_buddy(order, memflags, d) {
        request_node = MEMF_get_node(memflags);
        while (there are more nodes to try) {
            node = preferred_node_or_next_node();
            if (!node_allocatable_request(d, memflags, 1 << order, node))
                goto try_next_node;
            /* Find a zone on this node with a suitable buddy */
            for (zone = highest_zone; zone >= lowest_zone; zone--)
                for (j = order; j <= MAX_ORDER; j++)
                    if (pg = remove_head(&heap(node, zone, j)))
                        return pg;
         try_next_node:
            if (request_node != NUMA_NO_NODE && memflags & MEMF_exact_node)
                return NULL;
            /* Fall back to the next node and repeat. */
        }
    }

*******************************************
Helper functions for allocation with claims
*******************************************

For allocating memory while respecting claims, ``alloc_heap_pages()`` and
``get_free_buddy()``, use ``claims_permit_request()`` to check if the claims
permit the request before attempting to allocate memory. If the request is
permitted, the allocation proceeds, and after a successful allocation, the
``consume_allocation()`` function is used to consume the claims based on the
allocation.

claims_permit_request()
-----------------------

.. c:function:: bool claims_permit_request(const struct domain *d, \
                                           unsigned long avail_pages, \
                                           unsigned long claims, \
                                           unsigned int memflags, \
                                           unsigned long request, \
                                           nodeid_t node)

    :param d: domain for which to check
    :param avail_pages: pages available globally or on node
    :param claims: outstanding claims globally or on node
    :param memflags: memory allocation flags for the request
    :param request: pages requested for allocation
    :param node: node of the request or NUMA_NO_NODE for global
    :type d: const struct domain *
    :type avail_pages: unsigned long
    :type claims: unsigned long
    :type memflags: unsigned int
    :type request: unsigned long
    :type node: nodeid_t
    :returns: true if claims and available memory permit the request, \
              false otherwise.

    This function checks whether a memory allocation request can be satisfied
    given the current state of available memory and outstanding claims of the
    domain. It calculates the amount of unclaimed memory and determines if it
    is sufficient to satisfy the request.

    If not, it checks if the domain's claims can cover the shortfall, taking
    into account whether the request is for a specific node or global.

consume_allocation()
--------------------

.. c:function:: void consume_allocation(struct domain *d, \
                                        unsigned long allocation, \
                                        nodeid_t alloc_node)

    :param d: The domain for which to consume claims
    :param allocation: The number of pages allocated
    :param alloc_node: The node on which the allocation was made
    :type d: struct domain *
    :type allocation: unsigned long
    :type alloc_node: nodeid_t

    This function consumes claims for a domain based on a successful memory
    allocation. It first consumes from the global claim, then from the
    node-local claim for the allocation node, and finally from other
    node-local claims if necessary to satisfy the total allocation.

    It is used after a successful allocation to release claims in the same
    critical region that updates the free-page counters, ensuring that the
    domain's claiming state remains consistent with its updated memory usage.

**************************************
Offlining memory in presence of claims
**************************************

When offlining pages, Xen needs to ensure that the available memory on the
node or globally does not fall below the outstanding claims. If it does, Xen
recalls claims from domains until the accounting is valid again.

This is not a common case, but it can be triggered by privileged domains
using the Xen ``sysctl`` hypercall command ``XEN_SYSCTL_page_offline_op``,
and due to machine check events indicating bad or broken memory.

Offlining pages which are currently allocated does not reduce the available
memory immediately, but it marks the pages as offlining and causes freeing
them to mark them as offline, so memory marked for offlining will not become
available for allocation again, which is not a concern for claim invariants.

But when free pages are offlined, the available memory can fall below the
outstanding claims, which needs handling by recalling claims from domains as
part of the offlining process in the function ``reserve_offlined_page()``.

When offlining a page, ``reserve_offlined_page()`` checks if offlining
that page causes the available memory (on its node or globally) to fall
below the respective outstanding claims:

- If ``node_outstanding_claims[node]`` exceeds ``node_avail_pages[node]``,
  ``reserve_offlined_page()`` calls ``release_node_claim()`` to recall claims
  on that node from domains with claims on the node of the offlined buddy
  until the claim accounting of that node is valid again.

- If the total ``outstanding_claims`` exceeds the ``total_avail_pages``,
  ``reserve_offlined_page()`` calls ``release_global_claims()`` to recall
  global claims from domains with global claims
  until the global claims accounting is valid again.

It means that claim guarantees can be violated. However, it is a necessary
consequence of offlining memory because offlining of memory can become
necessary to maintain the stability of the system.

reserve_offlined_page()
-----------------------

.. c:function:: int reserve_offlined_page(struct page_info *head)

    :param head: The page being offlined
    :type head: struct page_info *
    :returns: 0 on success, or a negative error code on failure.

    This function is called during the offlining process to offline pages.

    If offlining a page causes the available memory to fall below
    the outstanding claims, it checks the node and global claim
    accounting and recalls claims from domains as necessary to ensure
    that the claim invariants hold after a buddy is offlined.
