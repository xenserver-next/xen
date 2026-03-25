.. SPDX-License-Identifier: CC-BY-4.0

.. header:: NUMA-aware Claim Sets

Background
----------

Xen's page allocator supports a **claims** API that allows a privileged
domain builder to reserve a portion of available memory before populating
the guest memory for a domain. This reservation is called a **claim** and
it ensures that the claimed memory remains available for the domain when
allocating it for the domain, even if other domains are also allocating
memory at the same time.

Installing claims is a privileged operation which is done by the domain
build process of Xen toolstacks. It is meant to be done by the domain
builder before it starts to populate the guest memory.

This prevents other domains from allocating memory that has been earmarked
for a domain under construction.
The Xen hypervisor maintains the per-domain claim state for pages claimed,
but not yet allocated for the domain.

When claim installation is successful, Xen updates the Xen's claim state
to reflect the new claim targets and protects the claimed memory so it
remains allocatable for the domain until it is either allocated for the
domain or the claim is released.

As Xen allocates pages for the domain, claims are consumed by reducing
the claim state of Xen by the size of the allocation.

Traditionally, the implementation supported only a single global claim
per domain (previously stored in ``d->outstanding_pages``) which is now
renamed to ``d->global_claims`` to track the total amount of memory
claimed by a domain without any NUMA awareness.

Claim sets
^^^^^^^^^^

Claim sets are a new design that extends the claims API to support installing
claims on multiple NUMA nodes atomically, with the option to also include a
claim for global memory (for memory that can come from any node).

This design adds **claim sets** for atomically installing a set of claims
not just on one, but optionally multiple NUMA nodes with the option to also
include a claim for global memory (for memory that can come from any node).

Legacy domain builders can continue to use the previous (now deprecated)
interface with its legacy semantics without any changes, while new domain
builders can take advantage of **claim sets** to install NUMA-aware claims.

Goals
^^^^^

The design's primary goals are:

1. Allow a domain builder to claim memory on multiple NUMA nodes atomically.
2. Preserve the legacy single-claim interface and semantics for existing
   toolstacks.
3. Use fast allocation-time claims protection in the allocator's hot paths.

Non-goals
^^^^^^^^^

Installing claims is a privileged operation which is done by the domain
build process of Xen toolstacks.
It is meant to be done before the guest memory is populated, so tracking
any existing allocations is out of scope for claims.
Installing legacy claims subtracts existing allocations from the installed
claim and the new design keeps it for legacy claims.
Intentionally, claim sets do not carry this behaviour going forward:

- Xen does not currently maintain a ``d->node_tot_pages[node]`` count,
  and the hypercall to exchange extents of memory with new memory makes such
  accounting relatively complicated. Implementing it would be possible but
  would require additional complexity and careful handling of edge cases.

- It allows claim sets design to use replacement semantics which are easier
  to reason about as the installed claims are always exactly the requested
  claims and not a delta of the requested claims and existing allocations.

- Replacement semantics also allows to easily support updating the locations
  of claims naturally. It allows converting a global claim into a node-local
  claim (if the node has sufficient capacity) or vice versa and even moving
  claims between nodes. Any subsequent claim set installation naturally
  resets the previous claims before installing the new claim set.

Headroom
^^^^^^^^

Memory allocations by Xen for the domain also consume from the claim:

If a domain builder stakes a claim before defining e.g. the number of vCPUs,
it must ensure that the claim is large enough to cover not only the guest
memory requirement but also the memory requirements of Xen for the domain
(for vCPU structures, grant tables, etc.) which also consume from the claim
as the domain is built. The exact amount of extra memory required depends on:

- the host architecture
- the configuration and features used by the domain (e.g. #vCPUS, PV vs HVM)
- and the features enabled by the Xen hypervisor on the host.

Pre-conditions
^^^^^^^^^^^^^^

The Domain's maximum memory limit must be set prior to staking a claim as the
sum of the already allocated pages and the claim must be within that limit.

Life-cycle of a claim
^^^^^^^^^^^^^^^^^^^^^

A claim can be released by the domain builder at any time, but it is typically
released after the domain build is complete, and the guest memory has been
allocated for the domain.

When using `libxenguest` to build the domain, `libxenguest` automatically
releases any remaining claim after the guest memory has been allocated
for the domain.

Xen also releases any remaining claim when the domain is destroyed.
