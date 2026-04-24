.. SPDX-License-Identifier: CC-BY-4.0

NUMA Claim Sets
===============

Design and implementation of NUMA-aware claim sets.

Status: Draft for review

This design first introduces the external behaviour of claim sets: how claims
are installed, how they protect allocations, and how they are redeemed.
It then covers the underlying accounting model and implementation details.

For readers following the design in order, the next sections cover the
following topics:

1.  :doc:`/designs/claims/use-cases` describes the use cases for claim sets.
2.  :doc:`/designs/claims/performance` describes the performance benefits
    of NUMA-aware claims for memory-intensive workloads in real customer
    environments for the described use cases.
3.  :doc:`/designs/claims/history` provides the development's historical context
4.  :doc:`/designs/claims/design` introduces the overall model and goals.
5.  :doc:`/designs/claims/installation` explains how claim sets are installed.
6.  :doc:`/designs/claims/protection` describes how claimed memory is
    protected during allocation.
7.  :doc:`/designs/claims/redeeming` explains how claims are redeemed as
    allocations succeed.
8.  :doc:`/designs/claims/accounting` describes the accounting model that
    underpins those steps.
9.  :doc:`/designs/claims/implementation` covers the implementation details of
    the above design.
10. :doc:`/designs/claims/edge-cases` covers edge cases and error handling.
11. :doc:`/designs/claims/glossary` defines the terms used in this design.

.. toctree:: :caption: Contents
   :maxdepth: 2

   use-cases
   performance
   history
   design
   installation
   protection
   redeeming
   accounting
   implementation
   edge-cases
   glossary

.. contents::
    :backlinks: entry
    :local:
