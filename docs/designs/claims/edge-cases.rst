.. SPDX-License-Identifier: CC-BY-4.0

Handling of Edge Cases
----------------------

Allocations using claims plus unclaimed memory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Previously, even though the host had enough unclaimed memory available
to satisfy a request, when the remaining claim of a domain was not fully
sufficient to satisfy an allocation request, the system would reject the
allocation request.

This caused the domain builder to reduce the order of pages used for
populating the domain's memory, from 1G pages to 2M pages, and eventually
to 4K pages which could still be allocated even in the presence of this
rejection logic, but at the cost of not using larger pages, causing a
runtime performance regression for the domain and the system in general
due to the increased number of pages in the TLB for such memory.

.. note:: See ``libxenguest``'s ``meminit_hvm()`` and ``meminit_pv()``
   functions for examples of this behaviour in the domain builder for
   populating the domain's memory with the largest possible pages.

Now, when when unclaimed memory is available to satisfy the reminder
of the request, the allocator allows the allocation to succeed.

This allows the domain builder to continue populating the domain with
larger pages as long as the combination of claims and unclaimed memory
permit it. This improves the performance of the domain and the system
in general in such scenarios.

Dying domains
^^^^^^^^^^^^^

When attempting to install a claim for a domain that is in the process
of dying, Xen needs to reject the claim installation request as it may
have already passed the point of releasing its claims. Installing claims
at this stage would cause the claimed memory to be lost to Xen permanently.

During review on the Xen-devel mailing list the request to not return
``-EINVAL`` for dying domains, as it is not an invalid request but rather
a valid request that cannot be fulfilled due to the domain's state. The
error code requested by reviewers was ``-ESRCH`` which indicates that the
domain cannot be found, which more accurately reflects the fact that the
domain is effectively gone for the purpose of installing claims.

For consistency, the legacy claim installation path using the single-claim
hypercall command ``XENMEM_claim_pages`` which briefly returned ``-EINVAL``
for dying domains in the unreleased master branch is also changed to return
``-ESRCH`` when attempting to install claims for a dying domain.
