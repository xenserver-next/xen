.. SPDX-License-Identifier: CC-BY-4.0

Xen Page Allocator Test Harness
===============================

Native integration test environment for the page allocator (page_alloc.c),
including the APIs that depend on it:

- the DOMCTL API (domctl.c) via entry points like do_domctl(),
- the XENMEM API (memory.c) via entry points like do_memory_op(),
- the SYSCTL API (sysctl.c) via entry points like do_sysctl().

The reason for writing this environment was to provide regression tests
for the NUMA memory claims series I posted recently, but in principle,
any function implemented in these modules can be tested with it.

The environment compiles test executables where the Xen code under test
is built into the same compilation unit as the test case source, allowing
full control over the environment, and stubbing, mocking, and wrapping of
functions as needed for the specific test scenarios.

For the runtime buddy allocator in page_alloc.c, the environment creates
a fresh synthetic Xen heap. Each test program can define a specific Xen
configuration like NUMA or UMA, and define the maximum number of nodes
and pages per node. The pages in the free lists for the test are set up
dynamically by each test case as needed for the specific scenario.

As the code under test is built as a native executable, all amenities
of native execution are available: It simply runs as a userspace program,
meaning test cases can be compiled and run on the spot without requiring
a running Xen hypervisor.

Natively, AddressSanitizer is enabled, every ASSERT() condition and
spin_{,un}lock() can be logged, you can wrap functions from your test
case, and you can debug the program directly with standard debuggers.

How Tests Work
--------------

Each test case starts from a clean allocator state and initializes a
synthetic frame table with pages on the free lists. After the allocator
operations under test, each test scenario checks the resulting state
through assertion helpers.

Typical checks include verifying the content of free lists (including
per-zone and per-node accounting), buddy order and alignment invariants,
and page-local state such as ``count_info`` and ``first_dirty``.

As running the tests after a change literally takes just seconds, it
can be used as a quick check for regressions during development. The
test cases can be easily extended to cover new scenarios as needed,
and integrating code coverage tools is straightforward.

Running The Tests
-----------------

The ``Makefile`` automatically discovers all ``test-*.c`` files
in this directory and builds one executable per source file.

Example to clean, build, and run all allocator tests:

.. code:: shell

    make -C tools/tests/alloc clean all run

To build and run a single test binary:

.. code:: shell

    make -C tools/tests/alloc run TARGETS=test-claims-basic

To build and run tests for multiple Xen target architectures (requires
suitable gcc cross-compilers and host binfmt support for the targets):

.. code:: shell

    make -C tools/tests/alloc run-archs

To build and run tests in the same way for a specific Xen target architecture:

.. code:: shell

    make -C tools/tests/alloc run-archs ARCHS=arm64-aarch64-linux-gnu

The ``run`` target executes the built tests when they are runnable on the
build host. If ``CC`` and ``HOSTCC`` differ, it will only attempt execution
when ``binfmt`` support for the target architecture is available.

For broader coverage, the ``run-archs`` target builds and runs the tests for
multiple Xen target architectures when suitable cross-compilers are installed.
