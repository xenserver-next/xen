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

C API by libxenctrl
-------------------

 .. c:function:: int xc_domain_claim_memory(xch, domid, nr_claims, claims *)

   :param xch:       The libxenctrl interface to use for the hypercall
   :param domid:     The ID of the domain for which to install the claim set
   :param nr_claims: The number of claims in the claim set
   :param claims:    The claim set to install for the domain
   :type xch:        xc_interface *
   :type domid:      uint32_t
   :type nr_claims:  uint32_t
   :type claims:     memory_claim_t *
   :returns:         0 on success, or a negative error code on failure.

   C API function for installing claim sets for a domain using the
   :expr:`XEN_DOMCTL_claim_memory` hypercall command.

   This function is part of the libxenctrl library and provides a convenient
   interface for :term:`domain builders` to install claim sets for a domain.

Usage example
~~~~~~~~~~~~~

 The example below shows how a domain builder can install a claim set and
 later replace or clear it. :c:expr:`memory_claim_t` contains an additional
 field for future expansion; zero-initialise the structure or use designated
 initializers to ensure forward compatibility.

 .. code-block:: C

  #include <xenctrl.h>

  void install_example_claims(xc_interface *xch, uint32_t domid)
  {
    /*
     * Claim 1024 pages on node 0, 1024 pages on node 1, and by setting the
     * total claim target to 3072 pages, an additional floating claim of 1024
     * pages which is never bound to any specific node is also installed.
      */
    memory_claim_t claims[] = {
      {.pages = 1024, .target = 0},
      {.pages = 1024, .target = 1},
      {.pages = 3072, .target = XEN_DOMCTL_CLAIM_MEMORY_TOTAL}
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
      {.pages = 0, .target = XEN_DOMCTL_CLAIM_MEMORY_TOTAL}
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
