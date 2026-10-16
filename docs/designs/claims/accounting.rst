.. SPDX-License-Identifier: CC-BY-4.0

Accounting
##########

.. contents:: Table of Contents
   :local:

.. note::
   Claims accounting state is only updated while holding the :c:var:`heap_lock`.
   See :ref:`designs/claims/accounting:Locking of the claims state` for details
   on the locks used to protect the claims accounting state.

This section formalises the internal state and invariants that Xen must
maintain to ensure correctness.


For readers following the design in order, the preceding sections are:

1. :doc:`/designs/claims/design` introduces the overall model and goals.
2. :doc:`/designs/claims/installation` explains how claim sets are installed.
3. :doc:`/designs/claims/protection` describes how claimed memory is protected
   during allocation.
4. :doc:`/designs/claims/redeeming` explains how claims are redeemed when
   allocations succeed.

Overview
^^^^^^^^

.. table:: Table 1: Claims accounting: All accesses, Aggregate state,
           and invariants protected by :c:var:`heap_lock`.
   :widths: auto

   ============ =========================================== =======================
   Level           Claims must be lower or equal to          the available memory
   ============ =========================================== =======================
   Total        :c:var:`outstanding_claims` =               :c:var:`total_avail_pages` =

                 = Aggregate state:
                  SUM() over all domains:                   Aggregate state:
                  SUM(:c:member:`domain.outstanding_pages`)   SUM(:c:var:`node_avail_pages`)

                Also, it is the sum of claims
                over all nodes:

                 = Aggregate state:
                  SUM(:c:expr:`node_outstanding_claims[*]`)
   Node         :c:expr:`node_outstanding_claims[node]`     :c:expr:`node_avail_pages[node]`

                  Aggregate state over all domains:          Aggregate of the free
                  SUM(:c:expr:`domain.claims[node]`)         lists of all zones on node
   Dom per-node :c:member:`domain.node_claims` =
                SUM(:c:expr:`domain.claims[node]`)          :c:expr:`node_avail_pages[node]`
   Total claims :c:member:`domain.outstanding_pages`        :c:var:`total_avail_pages`
   Memory limit :c:member:`domain.outstanding_pages`         Invariant: must be
                + :c:func:`domain_tot_pages`                 lower or equal to
                                                             :c:member:`domain.max_pages`
   ============ =========================================== =======================


Total claims and available memory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 These variables tracking the total claims and available memory in the system
 are aggregates of the actual per-node and per-domain values.


 They are only maintained for efficient checks in the allocator hot paths, to
 quickly determine if an allocation can be satisfied from unclaimed memory or
 if further checks are needed to determine if the claims of the domain can be
 used to free up memory for the allocation. This also ensures that the sum of
 all claims never exceeds the total free memory in the system.


 The number of unclaimed pages across all nodes in the system is derived as
 :c:var:`total_avail_pages` minus :c:var:`outstanding_claims`.
 This number is then used to:

 - Permit allocation requests if they can be satisfied from unclaimed pages.
 - Ensure that the sum of all claims never exceeds the total free memory.

 .. c:var:: unsigned long total_avail_pages

   Total available pages in the system across all NUMA nodes.
   It is the aggregate of the per-node available pages:
   :c:var:`total_avail_pages` = SUM(:c:expr:`node_avail_pages[MAX_NUMNODES]`)

 .. c:var:: unsigned long outstanding_claims

   The total sum of all claims across all domains.
   :c:var:`outstanding_claims` =
   SUM(:c:var:`domain.outstanding_pages`)

Per-node claims and available memory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 .. c:var:: unsigned long node_avail_pages[MAX_NUMNODES]

   Available pages for each NUMA node, including both free and claimed pages.
   This is used for validating that node claims do not exceed the available
   memory on the respective NUMA node.

 .. c:var:: unsigned long node_outstanding_claims[MAX_NUMNODES]

   The total claims across all domains for each NUMA node, indexed by node
   ID. This is maintained for efficient checks in the allocator hot paths.

This diagram illustrates the claims accounting state and the invariants:

Accounting diagram
^^^^^^^^^^^^^^^^^^

 .. mermaid:: invariants.mmd
   :caption: Diagram: Claims accounting state and invariants

Claims accounting state for each domain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 .. c:struct:: domain

   The main structure representing a domain in Xen. It includes the
   claims accounting state for the domain, including both host-wide
   and node-specific claims, as well as the maximum page limits for the
   domain and the lock protecting the domain's page allocation counts.

   While the domain's page counts are currently `unsigned int`, work is
   underway to change them to `unsigned long` to support larger page counts
   beyond 16 TB. The code is already designed to anticipate this change and
   work with either `unsigned int` or `unsigned long` page counts equally well.

   .. c:member:: unsigned int outstanding_pages

      The domain's total claim, representing the number of pages claimed
      for the domain.

   .. c:member:: unsigned int node_claims

      The total of the domain's node-affine claims, maintained for efficient
      checks in the allocator hot paths without needing to sum over the
      per-node claims each time. It is equal to the sum of
      :c:expr:`claims[MAX_NUMNODES]` for all nodes.

   .. c:member:: unsigned int claims[MAX_NUMNODES]

      The domain's claims for each :term:`NUMA node`, indexed by node ID.

      As the storage for ``struct`` :c:struct:`domain` is allocated using a
      dedicated page for each domain, this array allows for efficient and
      fast storage with direct indexing, without consuming any additional
      memory for an extra allocation.


      The claims for each node are used for NUMA-affine domains to specify
      the amount of memory claimed for each node, to ensure that the domain's
      claims for each node do not exceed the available memory on that node,
      and to allow the allocator to redeem claims from the appropriate nodes
      when allocating memory for the domain.

      .. literalinclude:: ../../../xen/common/domain.c
         :language: C
         :caption: Allocation of the domain structure in ``xen/common/domain.c``
         :start-at: alloc_domain_struct
         :end-at: }
         :emphasize-lines: 7, 12, 14
         :linenos:
         :lineno-match:

      The page allocated for ``struct`` :c:struct:`domain` is large enough
      to accommodate this array several times, even beyond the current
      :c:macro:`MAX_NUMNODES` limit of 64. It should be sufficient even for
      future expansion of the maximum number of supported NUMA nodes if
      needed. The allocation has a build-time assertion for safety to ensure
      that ``struct`` :c:struct:`domain` fits within the allocated page.


      The sum of these claims is stored in :c:member:`domain.node_claims`
      for efficient checks in the allocator hot paths which need to know
      the total number of node claims for the :term:`domain`.

   .. c:member:: unsigned int max_pages

      The maximum number of pages the domain is allowed to claim, set at
      domain creation time.

   .. c:member:: rspinlock_t page_alloc_lock

      Lock for checking :c:func:`domain_tot_pages` on top of new claims
      against :c:member:`domain.max_pages` when installing these new claims.
      This is a recursive spinlock to allow for nested calls into the allocator
      while holding it, such as when redeeming claims during page allocation.
      It is taken before :c:var:`heap_lock` when installing claims to ensure a
      consistent locking order and must not be taken while holding
      :c:var:`heap_lock` to avoid deadlocks.

   .. c:member:: nodemask_t node_affinity

      A :c:type:`nodemask_t` representing the set of NUMA nodes the domain
      is affine to. This is used for efficient checks in the allocator hot
      paths to quickly get the set of nodes a domain is affine to for
      memory allocation decisions.

Claims accounting invariants
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   Xen must maintain the following invariants at all times to ensure correctness
   of claims accounting:

 - For all claims, including node-affine and host-wide claims:
    :c:var:`outstanding_claims` :math:`\le` :c:var:`total_avail_pages`

 - For node-specific claims:
    :c:expr:`node_outstanding_claims[alloc_node]` :math:`\le`
    :c:expr:`node_avail_pages[alloc_node]`

 - For a domain's overall claims:
    :c:var:`domain.outstanding_pages` +
    :c:var:`domain_tot_pages` :math:`\le` :c:var:`domain.max_pages`

    See :doc:`redeeming` for more information on this invariant.

Constants
^^^^^^^^^

 .. c:macro:: MAX_NUMNODES

   The maximum number of NUMA nodes supported by Xen. Used for validating
   node IDs in the :c:type:`memory_claim_t` entries of claim sets.
   When Xen is built without NUMA support, it is 1.

   The default on x86_64 is 64 which is sufficient for current hardware and
   allows for efficient storage of e.g. the :c:var:`node_online_map` for
   online nodes and :c:member:`domain.node_affinity` in a single 64-bit value,
   and in the :c:expr:`domain.claims[MAX_NUMNODES]` array.

   ``xen/arch/Kconfig`` limits the maximum number of NUMA nodes to 64. While
   Xen can be compiled for up to 254 nodes, configuring machines to split
   the installed memory into more than 64 nodes would be unusual.
   For example, dual-socket servers, even when using multiple chips per CPU
   package should typically be configured for 2 NUMA nodes by default.

 .. c:var:: nodemask_t node_online_map

   A bitmap representing which NUMA nodes are currently online in the system.
   This is used for validating that claims are only made for online nodes and
   for efficient checks in the allocator hot paths to quickly determine which
   nodes are online. Currently, Xen does not support hotplug of NUMA nodes,
   so this is set at boot time based on the platform firmware configuration
   and does not change at runtime.

Types
^^^^^

 .. c:type:: uint8_t nodeid_t

   Type for :term:`NUMA node` IDs. It is passed to Xenctrl using the
   :c:var:`mem_flags` argument of :c:func:`xc_domain_populate_physmap()`
   and passed to Xen in this form.

   It allocates 8 bits in the flags for the node ID, which limits the
   theoretical maximum value of :c:macro:`CONFIG_NR_NUMA_NODES` at 254
   (255 is :c:macro:`NUMA_NO_NODE`), which is far beyond the current
   maximum of 64 supported by Xen and should be sufficient for all
   practical purposes. This also allows for efficient storage of NUMA
   nodes in arrays indexed by node ID and in :c:type:`nodemask_t` bitmaps
   :c:var:`node_online_map` and :c:member:`domain.node_affinity` for
   efficient checks in the allocator hot paths.

 .. c:type:: nodemask_t

   A bitmap representing a set of NUMA nodes, used for status information
   like :c:var:`node_online_map` and the :c:member:`domain.node_affinity`,
   and to track which nodes are online and which nodes are in a domain's
   node affinity.

Memflags
^^^^^^^^

 .. c:type:: memflags

    Flags for memory allocation requests that can affect the allocation
    behaviour, such as node preference and whether the request is for an
    exact node.

 .. c:macro:: MEMF_no_owner

    Flag for memory allocation requests to indicate that the allocation
    shall not be owned by a domain, and as part of that,
    :c:macro:`MEMF_no_refcount` is also set.

 .. c:macro:: MEMF_no_refcount

    Flag for memory allocation requests to indicate that the request is not
    reference-counted to a domain's memory allocation state, and as part of
    that, claims of a domain cannot be used to protect and redeem the
    allocation using claims. This is used for requests which are not for
    domains or which explicitly bypass reference-counting for other reasons.

 .. c:macro:: MEMF_no_scrub

    Flag for memory allocation requests to indicate that the allocated memory
    should not be scrubbed (zeroed) before being used. This is used for
    performance reasons for certain types of allocations where the caller
    guarantees that the memory will be properly initialized before use.

Locking of the claims state
^^^^^^^^^^^^^^^^^^^^^^^^^^^

 .. :c:member:: domain.page_alloc_lock

    If :c:var:`domain.page_alloc_lock` is needed, e.g. to check
    :c:func:`domain_tot_pages` on top of new claims against
    :c:var:`domain.max_pages` for the domain, it needs to be taken before
    :c:var:`heap_lock` for consistent locking order to avoid deadlocks.

 .. c:var:: spinlock_t heap_lock

    Lock for all heap operations including claims. It protects the claims
    state and invariants from concurrent updates and ensures that checks
    in the allocator hot paths see a consistent view of the claims state.

Helper functions
^^^^^^^^^^^^^^^^

 .. c:function:: inline unsigned int domain_tot_pages(struct domain *d)

   :param d: The domain for which to calculate the total pages.
   :type d: struct domain *
   :returns: The total pages allocated to the domain.

   This function is used for validating that an allocation and the domain's
   claims do not exceed :c:member:`domain.max_pages`.
