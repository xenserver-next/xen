.. SPDX-License-Identifier: CC-BY-4.0

NUMA Claims
===========

Design and implementation of NUMA-aware claim sets.

Status: Draft for review

This design first introduces the external behaviour of claim sets: how claims
are installed, how they protect allocations, and how they are redeemed.
It then covers the underlying accounting model and implementation details.

For readers following the design in order, the next sections cover these
topics:

1.  :doc:`/designs/claims/use-cases` describes the use cases for claim sets.
2.  :doc:`/designs/claims/performance` describes the performance test results.
3.  :doc:`/designs/claims/development` provides the development history and future work.
4.  :doc:`/designs/claims/design` introduces the overall model and goals.
5.  :doc:`/designs/claims/installation` describes how claim sets are installed.
6.  :doc:`/designs/claims/protection` describes how claimed memory is
    protected during allocation.
7.  :doc:`/designs/claims/redeeming` explains how claims are redeemed when
    allocations succeed.
8.  :doc:`/designs/claims/accounting` describes the accounting model that
    underpins those steps.
9.  :doc:`/designs/claims/implementation` documents the functions used for the
    implementation.
10. :doc:`/designs/claims/terminology` defines the terms used in this design.

.. toctree:: :caption: Contents
   :maxdepth: 2

   use-cases
   performance
   development
   design
   installation
   protection
   redeeming
   accounting
   implementation
   terminology

.. contents::
    :backlinks: entry
    :local:
