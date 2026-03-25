.. SPDX-License-Identifier: CC-BY-4.0

Example Usage
-------------

A builder that wants 1024 pages on node 0, 1024 pages on node 1,
and an additional 256 pages that may come from anywhere can submit
a claim array of the form:

.. code-block: C

      [
            { .pages = 256,  .node = XEN_DOMCTL_CLAIM_MEMORY_GLOBAL },
            { .pages = 1024, .node = 0 },
            { .pages = 1024, .node = 1 },
      ]

A later update can atomically replace that with a different distribution, for
example moving part of node 1's claim to node 2 or dropping the global
fallback claim entirely.
