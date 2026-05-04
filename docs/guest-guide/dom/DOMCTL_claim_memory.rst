.. SPDX-License-Identifier: CC-BY-4.0

claim_memory
************

 .. c:macro:: XEN_DOMCTL_claim_memory

  Hypercall command for installing claim sets for a domain.

  This command allows :term:`domain builders` to install a :term:`claim set`
  for a domain, which the Xen hypervisor tracks and enforces during memory
  allocation.

  The claimed memory is protected from other allocations and the domain's
  memory requirements can be met even when other parallel domain builders
  are also allocating memory for other domains in parallel.

  :ref:`designs/claims/installation:Claim set installation` describes how the
  hypervisor processes the claim sets installed via this hypercall command.

Hypercall API
-------------

See :ref:`designs/claims/installation:Claim sets`
for more details on the claim sets data structure.

Definitions
^^^^^^^^^^^

Mode
~~~~
 .. c:macro:: XEN_DOMCTL_CLAIM_MEMORY_SET

    Install the given claim set for the domain.

 .. c:macro:: XEN_DOMCTL_CLAIM_MEMORY_GET

    Retrieve the claim set for the current claims of the domain.

Target selectors
~~~~~~~~~~~~~~~~
  .. c:macro:: XEN_DOMCTL_CLAIM_MEMORY_UNPINNED

    Special target selector for unpinned claims,
    which can be satisfied from any NUMA node.

  .. c:macro:: XEN_DOMCTL_CLAIM_MEMORY_LEGACY

    Special target selector for legacy claims, which is interpreted as the
    total memory target for the domain, with existing allocations subtracted
    from it to determine the domain's new total unpinned outstanding claim.
    It is provided for compatibility with existing :term:`domain builders`
    and can only be used in a single-entry claim set.

domctl.h structure
^^^^^^^^^^^^^^^^^^

 .. code-block:: C

    struct xen_memory_claim {
        uint64_aligned_t pages; /* Number of pages to claim */
        uint32_t target; /* NUMA node or claim type like legacy or unpinned */
        uint32_t cmd;    /* Command reserved for future use, initialize to 0 */
    };
    typedef struct xen_memory_claim memory_claim_t;
    DEFINE_XEN_GUEST_HANDLE(memory_claim_t);

    /* Special claim targets for the target field of memory_claim_t */
    #define XEN_DOMCTL_CLAIM_MEMORY_UNPINNED 0x80000000U /* Node-agnostic claims */
    #define XEN_DOMCTL_CLAIM_MEMORY_LEGACY   0x40000000U /* Legacy semantics */

    /*
     * XEN_DOMCTL_claim_memory
     *
     * Install a claim set to claim memory for a guest domain. Claims work like
     * tickets in exchange for allocating memory for a domain later.
     */
    struct xen_domctl_claim_memory {
        /* IN/OUT: Array of struct xen_memory_claim */
        XEN_GUEST_HANDLE_64(memory_claim_t) claim_set;
        /* IN/OUT: Number of records in the claim_set array handle. */
        uint32_t nr_entries;
        uint32_t mode;
    #define XEN_DOMCTL_CLAIM_MEMORY_GET 0U /* Get a claim set for the domain. */
    #define XEN_DOMCTL_CLAIM_MEMORY_SET 1U /* Set a claim set for the domain. */
    };


C API by libxenctrl
-------------------

 .. c:function:: int xc_domain_claim_memory(xch, domid, mode, nr_entries, \
                                            claim_set)

   :param xch:       The :term:`libxenctrl` interface to use for the hypercall
   :param domid:     The ID of the domain for which to install the claim set
   :param mode:      The mode for the claim set installation
   :param nr_entries: The number of entries in the claim set
   :param claim_set:  The claim set to install for the domain
   :type xch:        xc_interface *
   :type domid:      uint32_t
   :type mode:       uint32_t
   :type nr_entries: uint32_t *
   :type claim_set:  memory_claim_t *
   :returns:         0 on success, or a negative error code on failure.

   C API function for installing or retrieving claim sets for a domain
   using the :expr:`XEN_DOMCTL_claim_memory` hypercall command.

   This function allows :term:`domain builders` to install a
   :term:`claim set` for a domain, which the Xen hypervisor
   tracks and enforces during memory allocation and can also
   be used to retrieve the current claim set for a domain.

   When mode is :c:macro:`XEN_DOMCTL_CLAIM_MEMORY_SET`, the former mode
   is used, where the function validates and installs the given claim set.
   ``nr_entries`` specifies the number of entries in the ``claim_set`` array,
   and ``claim_set`` points to the array of :c:type:`memory_claim_t` entries.

   When mode is :c:macro:`XEN_DOMCTL_CLAIM_MEMORY_GET`, the function
   retrieves the current claim set into the memory pointed to by ``claim_set``.
   The number of claims retrieved is stored in the variable pointed to by
   ``nr_entries``.

   This function is part of the :term:`libxenctrl` library.

   Corresponding OCaml bindings are also available for this function in the
   :term:`Xenctrl` OCaml library, providing a convenient interface for OCaml
   :term:`domain builders` to install claim sets for a domain.

C API Usage example
^^^^^^^^^^^^^^^^^^^

 The example below shows how a domain builder can install a claim set and
 later replace or clear it. :c:expr:`memory_claim_t` contains an additional
 field for future expansion; zero-initialise the structure or use designated
 initializers to ensure forward compatibility.

 .. code-block:: C

  #include <xenctrl.h>

  void install_example_claims(xc_interface *xch, uint32_t domid)
  {
    /*
     * Claim 1024 pages on node 0, 1024 pages on node 1, and by setting
     * the total claim target to 3072 pages, an additional host-wide claim of
     * 1024 pages which is never bound to any specific node is also installed.
     */
    memory_claim_t claims[] = {
      {.pages = 1024, .target = 0},
      {.pages = 1024, .target = 1},
      {.pages = 1024, .target = XEN_DOMCTL_CLAIM_MEMORY_UNPINNED},
    };
    xc_domain_claim_memory(xch, domid, ARRAY_SIZE(claims), claims);

    /* Replace the claim set with claims on nodes 1, 2, and 3 */
    memory_claim_t claims2[] = {
      {.pages = 1024, .target = 1},
      {.pages = 1024, .target = 2},
      {.pages = 1024, .target = 3},
    };
    xc_domain_claim_memory(xch, domid, ARRAY_SIZE(claims2), claims2);

    /* Release all remaining claims once the domain is built */
    memory_claim_t clear[] = {
      {.pages = 0, .target = XEN_DOMCTL_CLAIM_MEMORY_UNPINNED}
    };
    xc_domain_claim_memory(xch, domid, ARRAY_SIZE(clear), clear);
  }

Using the Xenctrl OCaml bindings
--------------------------------

 The OCaml bindings for libxenctrl also provide an interface for installing
 claim sets using the :c:expr:`XEN_DOMCTL_claim_memory` hypercall command.

 The example below shows how to install a claim set and later release it
 using the OCaml bindings.

 .. code-block:: OCaml

  let install_example_claims xch domid =
    let claims = [|
      { Xenctrl.pages = 1024L; node = 0l };
      { Xenctrl.pages = 1024L; node = 1l };
      { Xenctrl.pages = 3072L; node = XEN_DOMCTL_CLAIM_MEMORY_TOTAL };
    |] in
    Xenctrl.domain_claim_memory xch domid claims;

  let release_all_claims xch domid =
    let clear = [|
      { Xenctrl.pages = 0L; node = XEN_DOMCTL_CLAIM_MEMORY_TOTAL };
    |] in
    Xenctrl.domain_claim_memory xch domid clear

Call sequence diagram
---------------------

 The following sequence diagram illustrates the call flow for claiming memory
 for a domain using this hypercall command from an OCaml domain builder:

 .. mermaid:: DOMCTL_claim_memory-seqdia.mmd
   :caption: Sequence diagram: Call flow for claiming memory for a domain

Claim workflow
--------------

 This diagram illustrates a workflow for claiming and populating memory:

 .. mermaid:: DOMCTL_claim_memory-workflow.mmd
   :caption: Workflow diagram: Claiming and populating memory for a domain

Used functions & data structures
--------------------------------

 This diagram illustrates the key functions and data structures involved in
 installing claims via the :c:expr:`XEN_DOMCTL_claim_memory` hypercall command:

 .. mermaid:: DOMCTL_claim_memory-data.mmd
   :caption: Diagram: Function and data relationships for installing claims
