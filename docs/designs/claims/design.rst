.. SPDX-License-Identifier: CC-BY-4.0

#############
Claims Design
#############

.. contents:: Table of Contents
    :backlinks: entry
    :local:

Xen's page allocator supports a **claims** API that allows a privileged
domain builder to reserve a portion of available memory before populating
the guest memory for a domain. This reservation is called a **claim**.
It ensures that the claimed memory remains available for the domain when
allocating it, even if other domains are allocating memory at the same
time.

Installing claims is a privileged operation performed by domain builders
before the guest memory is populated. This prevents other domains from
allocating memory earmarked for a domain under construction. The Xen
hypervisor maintains the per-domain claim state for pages that are
claimed but not yet allocated.

When claim installation succeeds, Xen updates the claim state to reflect
the new targets and protects the claimed memory until it is allocated or
the claim is released. As Xen allocates pages for the domain, claims are
consumed by reducing the claim state by the size of each allocation.

Traditionally, the implementation supported only a single global claim per
domain (previously stored in ``d->outstanding_pages``). This is now
represented by ``d->global_claims``, which records the total memory claimed
by a domain without NUMA awareness.

**********
Claim sets
**********

Claim sets extend the claims API to support installing claims on multiple
NUMA nodes atomically. They may optionally include a global claim (memory
that can come from any node).

Legacy domain builders can continue to use the previous (now deprecated)
interface with its legacy semantics without changes. New domain builders
can take advantage of claim sets to install NUMA-aware claims.

*****
Goals
*****

The design's primary goals are:

1. Allow a domain builder to claim memory on multiple NUMA nodes atomically.

2. Preserve the legacy single-claim interface and semantics for existing
   domain builders.

3. Use fast allocation-time claims protection in the allocator's hot paths.

4. Ensure that the claim sets API is flexible enough to support various
   domain building strategies, including those that require global claims
   and those that require NUMA-aware claims without forcing all claims to
   be NUMA-node specific.

5. Still support the classic use case of claiming memory without NUMA
   awareness. It is which is still a possible use case for some domain builds,
   especially when memory requirements exceed the free memory of a single
   NUMA node, and required for backwards compatibility with existing domain
   builders.

   While populating memory for such a domain, the domain builder can still
   use the domain's NUMA affinity to define a set of desired NUMA nodes to
   allocate from and even specify which node to prefer for a specific
   allocation, but the claim itself is not specific to any NUMA node.

   This goal means that we cannot remove variables or code for the global
   claims like the ``outstanding_claims`` variable, which is used to track
   the total amount of claimed memory for of all domains on the host,
   including both global claims and NUMA-node-specific claims, but their
   calculation needs to be updated to also include node-specific claims.

   The global outstanding_claims variable counts the host-level claimed pages.

6. Support parallel domain builds where some domains are built with node-local
   claims while other domains are built in parallel with global claims.

   This is especially useful for use cases where some domains need to
   have prioritized access to memory on specific NUMA nodes for performance
   reasons, while other domains can be built more flexibly with global claims
   that can be satisfied from any available memory on the host.

   Such parallel domain builds are common in scenarios where multiple
   domains are being constructed simultaneously, each with different
   memory requirements and NUMA preferences.

   Two examples leading to parallel domain builds are:

   - `Boot storms`, where many domains are being booted or rebooted at
     the same time, and some of those domains have specific NUMA
     requirements while others do not.

   - `Host evacuation`, where many domains are being migrated away from
     a host at the same time, and some of those domains have specific
     NUMA requirements while others do not.

   These scenarios are common in large-scale deployments where hosts are
   being managed dynamically, and the ability to support parallel domain
   builds with a mix of global and NUMA-aware claims is essential for
   efficient resource management and performance optimization.

   In those deployments, many domain builders are building domains in
   parallel, and some of those domain builders need to use claim sets
   to install NUMA-aware claims for their domains, while other domain
   builders can rely on, or fall back to global claims for their domains.

   These are the scenarios where the flexibility of claim sets is required,
   and without claim sets, we would not be able to support such use cases
   with optimal NUMA performance after domain creation effectively.

*****************************
Implementation considerations
*****************************

The `original implementation of single-node claims by Alejandro Vallejo <v1_>`_
introduced the initial support for NUMA-node-specific claims, allowing domain
builders to claim memory on specific NUMA nodes. However, it did not include
support for claiming memory on multiple NUMA nodes atomically.

Roger Pau Monné reviewed the original implementation of single-node claims
and `suggested to extend the API to support multi-node claim sets <v1mul_>`_
sets from the start to make it future-proof and allow for claiming memory
on multiple NUMA nodes:

  `But why is this a single node?  The interface should allow for a
  domain to claim memory from multiple different nodes.`

  `The interface here seems to be focused on domains only being allowed
  to allocate from a single node, or otherwise you must first allocate
  memory from a node before moving to the next one (which defeats the
  purpose of claims?).`

  `I think we want to instead convert d->outstanding_pages into a
  per-node array, so that a domain can have outstanding claims for
  multiple NUMA nodes?`

  `The hypercall interface becomes a bit awkward then, as the toolstack
  has to perform a different hypercall for each memory claim from a
  different node (and rollback in case of failure).  Ideally we would
  need to introduce a new hypercall that allows making claims from
  multiple nodes in a single locked region, as to ensure success or
  failure in an atomic way.``

  -- Roger Pau Monné

This allows for reliable first-come, first-served claims sets installation,
which is why this design implements his suggestion as-is, with two details:

- ``d->outstanding_pages`` is `renamed` to ``d->global_claims`` to better
  reflect its purpose of tracking global claims that are not specific to
  any NUMA node, while the new per-node claim state is tracked in a new array
  ``d->claims[node]``.

- For the allocation hot path, the sum of ``d->claims[node]`` is maintained
  in a new variable ``d->node_claims`` to allow for fast checks against the
  total claimed memory for the domain without needing to sum the per-node
  claims on each allocation.

*********
Non-goals
*********

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
  Because staking claims after allocations is not a supported use case,
  subtracting existing allocations at installation time is unnecessary.

- Claim sets are a new API and can provide more intuitive semantics
  without subtracting existing allocations from installed claims. This
  also simplifies the implementation and makes it easier to maintain.

Stability and extensibility of the hypercall
===========================================

While the claim sets hypercall is designed to be flexible and powerful
for privileged domain builders, it is not intended to be a stable interface
for general use.

The users of this hypercall are privileged domain builders that use the
unstable ``domctl`` hypercall interface using the ``libxenctrl`` library.
This is an interface that is only provided for privileged domain builders
and is not exposed to other domains.

Being defined as a stable interface like ``XEN_DOMCTL_get_domain_state``
is not a goal because the latter is only exported to ``libxenmanage``
for ``xenstored`` without using ``libxenctrl`` at all, as it aims to
work independent of the hypervisor version.

Such stability is not required for the claim sets hypercall, as it is only
used by privileged domain builders that can be updated together with the
hypervisor to use the new API, and it is not intended for general use by
other domains or tools.

The extra space included in the claim sets hypercall allows for adding new
features or parameters to the claim sets API in the future without breaking
compatibility with existing domain builders that use the current version of
the API, but it does not imply that the API itself is intended to be stable
for general use. It could change in the future if needed to support new
features or requirements.

********
Headroom
********

Memory allocations by Xen for the domain also consume claims.

- If a domain builder stakes a claim before allocating resources (for
  example, setting the number of vCPUs), the resulting allocations for
  Xen's memory needs (vCPU structures, grant tables, etc.) also consume
  from the installed claims.
- The exact extra memory required for these structures depends on the
  host architecture, the domain configuration, and the Xen features that
  are enabled.

********************
Life-cycle of claims
********************

A claim can be released by the domain builder at any time, but domain builders
are expected to release claims after completing the domain build. Examples:

- Domain builders call claims installation with ``pages`` set to ``0`` to
  release claims.
- ``libxenguest``'s ``meminit`` API releases any remaining claims after
  populating memory.
- Xen releases remaining claims itself when it destroys a domain.

**********
References
**********

1. The `original feature <v1_>`_ implemented by Alejandro Vallejo:

   This implementation introduced the initial support for NUMA-node-specific
   claims, allowing domain builders to claim memory on specific NUMA nodes.

   The implementation was based on passing the NUMA node index in the
   ``memflags`` parameter of the existing claims hypercall, which was
   a somewhat limited approach that did not allow for claiming memory
   on multiple NUMA nodes atomically.

   It laid the groundwork for future extensions to support multi-node claim
   sets, but it did not include support for claiming memory on multiple
   NUMA nodes.

2. The suggestion to `extend the API to support multi-node claim sets <v1mul_>`_
   by Roger Pau Monné:

   This suggestion was made in the context of the original implementation of
   single-node claims, and it highlighted the need for a more flexible API
   that can support claiming memory on multiple NUMA nodes atomically.

   The suggestion emphasized that even if the initial implementation only
   supports single-node claims, designing the API with future extensions in
   mind is important to allow for adding multi-node claim set support later
   without breaking compatibility with existing domain builders.

   The idea was to introduce a new hypercall API that can handle multi-node
   claim sets from the start, even if the initial implementation only handles
   single-node claims, to ensure that the API is future-proof and can evolve
   to meet the needs of domain builders who require more complex claim
   management across multiple NUMA nodes.

3. The `v4 PATCH submission <v4_>`_ of the implementation with single-node
   claims which led to multiple suggestions to replace it with multi-node
   claim sets.

   Example:
   `[v4,03/10] xen/page_alloc: Implement NUMA-node-specific claims <v4-03_>`_:

   - Like the earlier v2 and v3 series, this series implemented the
     API for NUMA-node-specific claims based on a new hypercall for
     passing an array of claims, allowing domain builders to claim
     memory on specific NUMA nodes.

   - However, this implementation only supported claiming memory on
     a single NUMA node.

   - It received multiple suggestions from the community to replace the
     single-node claims implementation with a more flexible multi-node
     claim sets that can support claiming memory on multiple NUMA nodes.

.. _v1:
   https://patchew.org/Xen/20250314172502.53498-1-alejandro.vallejo@cloud.com/
.. _v1mul:
   https://lists.xenproject.org/archives/html/xen-devel/2025-06/msg00484.html
.. _v4:
    https://lists.xenproject.org/archives/html/xen-devel/2026-02/msg01387.html
.. _v4-03: https://patchwork.kernel.org/project/xen-devel/
   patch/6927e45bf7c2ce56b8849c16a2024edb86034358.1772098423
   .git.bernhard.kaindl@citrix.com/
