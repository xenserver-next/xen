.. SPDX-License-Identifier: CC-BY-4.0

Development History
*******************

.. note:: This section provides historical context on the development of
   NUMA-aware claims, including previous implementations and feedback received,
   to give a better understanding of the design decisions made in the current
   implementation.

Version history
---------------

The initial `implementation of single-node claims <v1_>`_ by Alejandro Vallejo
used legacy claims hypercall :ref:`XENMEM_claim_pages` and passed a NUMA node
in the existing NUMA node bits of :c:expr:`xen_memory_reservation.mem_flags`
added the flag ``d->claim_node`` to ``struct`` :c:struct:`domain` which
defined the target node for the domain's claims.

.. epigraph::

   Roger Pau Monné reviewed it and proposed `proposed an initial multi-node
   claim-sets specification <v1m_>`_ that inspired this design:

    The interface here seems to be focused on domains only being allowed
    to allocate from a single node, or otherwise you must first allocate
    memory from a node before moving to the next one (which defeats the
    purpose of claims?).

    I think we want to instead convert d->outstanding_pages into a
    per-node array, so that a domain can have outstanding claims for
    multiple NUMA nodes?

    The hypercall interface becomes a bit awkward then, as the toolstack
    has to perform a different hypercall for each memory claim from
    a different node (and rollback in case of failure).  Ideally we would
    need to introduce a new hypercall that allows making claims from
    multiple nodes in a single locked region, as to ensure success or
    failure in an atomic way.

    -- Roger Pau Monné

   This led to the `v2 <v2_>`_ and `v3 <v3_>`_ series adding a new hypercall
   API which designated passing an array of claims, allowing for a more
   flexible claim set design targeting multiple NUMA nodes and floating claims,
   but only supported a single claim per domain at the time.

.. sidebar:: Feedback and suggestions for multi-node claim sets

   The initial implementations of single-node claims received feedback from the
   community, with multiple suggestions to extend the API to support `multi-node
   claim sets <v1m_>`_. This feedback highlighted the need for a more flexible
   and extensible design that could accommodate claims on multiple NUMA nodes.

Between v3 and v4, `Roger Pau Monné and Andrew Cooper developed and merged
several critical fixes <fix1_>`_ for Xen's overall claims implementation.
These fixes also allowed Roger to improve the implementation for redeeming
claims during domain memory allocation. With a further suggestion by
Bernhard Kaindl, this enabled a fully working implementation that protected
claimed memory against parallel allocations by other domain builders.

With the `v4 series <v4_>`_, we submitted the combined work that completed the
fixes for protecting claimed memory on NUMA nodes. The review process indicated
that supporting multiple claim sets would require a `redesign <v4-03_>`_ of
claim installation and management, which led to this design document.

The `v5 series <v5_>`_ implemented the `Claim Sets Design Version 1 <d1>`_ and
the `v6 series <v6_>`_ implemented the `Claim Sets Design Version 2 <d2>`_.
The differences between the two versions are that with design version 2,
the initial term "consuming claims" was improved to "redeeming claims"
and the term "retiring claims" was improved to "deducting claims".

Testing
-------

The basis of the `v4 series <v4_>`_ is included in the XenServer XS9 preview
release, and besides functional product testing, it has been tested to
meet the performance expectation of customers from improved NUMA placement.

With the `v6 series <v6_>`_, the claim a comprehensive set of functional system
tests was added to the submission. Also, `a separate host-side integration test
suite <tv2_>`_ for validating the `v6 series <v6_>`_ was posted.

Further development
-------------------

Based on review feedback, there is the wish to normalise the page counts of
the page allocator to `unsigned long`. A `first patch <u1_>`_ in this direction
was posted to normalize the types of :c:expr:`total_avail_pages` and
:c:expr:`outstanding_claims` to ``unsigned long`` in the page allocator.

Acknowledgements
----------------

The claim sets design builds on the single-node claims implementation
described above and the feedback it generated. The following people
should be acknowledged for their contributions:

- *Edwin Török* for developing the `initial best-effort NUMA placement
  feature in the XAPI toolstack <xapi_>`_, which inspired the initial
  implementation of NUMA-aware claims, and his work in productizing and
  validating the integration of NUMA claims with the XAPI toolstack.

- *Alejandro Vallejo* for starting the development of the NUMA claims series.

- *Jan Beulich* for providing review suggestions that led to many improvements.

- *Roger Pau Monné* for reviewing the initial implementation, `proposing
  the initial multi-node claim-sets specification <_v1>`_, developing and
  merging `critical fixes <fix1_>`_ upstream that enabled product-quality
  support for single-node claims which is the basis of the multi-node
  claim sets implementation.

- *Andrew Cooper* for integrating and validating the work internally,
  helping to stabilise and productise the single-node implementation.

- *Bernhard Kaindl* for collaborating on the single-node implementation,
  developing the claim sets hypercall since version 2, designing and
  implementing the multi-node claim sets design, the functional system-level
  test suite and the host-side integration test suite for validating the
  claim sets implementation.

- *Marcus Granado* for leading the development effort inside XenServer for
  productising the single-node claims implementation, for providing feedback
  and suggestions for improving the design and implementation. This included
  coordinating the work of multiple contributors and stakeholders, integrating
  the work into XenServer products and ensuring it meets customer requirements.

.. _xapi: https://xapi-project.github.io/new-docs/toolstack/features/NUMA
.. _fix1:
   https://lists.xenproject.org/archives/html/xen-devel/2026-01/msg00164.html
.. _v1:
   https://patchew.org/Xen/20250314172502.53498-1-alejandro.vallejo@cloud.com/
.. _v1m:
   https://lists.xenproject.org/archives/html/xen-devel/2025-06/msg00484.html
.. _v2: https://lists.xen.org/archives/html/xen-devel/2025-08/msg01076.html
.. _v3: https://patchew.org/Xen/cover.1757261045.git.bernhard.kaindl@cloud.com/
.. _v4:
    https://lists.xenproject.org/archives/html/xen-devel/2026-02/msg01387.html
.. _v4-03: https://patchwork.kernel.org/project/xen-devel/
   patch/6927e45bf7c2ce56b8849c16a2024edb86034358.1772098423
   .git.bernhard.kaindl@citrix.com/
.. _d1:
   https://bernhard-xen.readthedocs.io/en/claim-sets-v1-design/designs/claims
.. _d2:
   https://bernhard-xen.readthedocs.io/en/claim-sets-v2-design/designs/claims
.. _v5: https://patchwork.kernel.org/project/xen-devel/list/?series=1078053
.. _v6: https://patchwork.kernel.org/project/xen-devel/list/?series=1081139
.. _tv2: https://patchwork.kernel.org/project/xen-devel/list/?series=1083329
.. _u1: https://patchwork.kernel.org/project/xen-devel/list/?series=1084344