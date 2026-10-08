# 05 - libxc: add xc_domain_set_memory_claims()

Commit `76a07d2201` (`58cdb588e8` before the rebase over the reworded patches 1 and 2; message and tree unchanged).

**Result:** no change needed.

## Code review

- The wrapper zero-initialises the domctl (so `pad` stays zero, which the hypervisor checks):
  - sets `nr_entries` and the guest handle,
  - and returns the result of `do_domctl()` (0, or -1 with errno set).

- Bounce buffer:
  - the hypervisor only reads the array, so `DECLARE_HYPERCALL_BOUNCE_IN()` is the right direction.
  - The macro casts the `const` pointer to `void *`:
    - so `const xen_domctl_memory_claim_t *` compiles without a warning.
  - `xc_hypercall_bounce_pre()` does not bounce a NULL buffer:
    - so `nr == 0` with `claims == NULL` (the release case in the header comment) works.
  - `xc_hypercall_bounce_post()` runs on the success and the failure path of the call.

- The prototype and the wrapper follow the existing `xc_domain_*` style.

- The header comment matches `domctl.h`:
  - set on a domain without outstanding claims,
  - target is a node or `XEN_DOMCTL_MEMORY_CLAIM_TARGET_HOST`,
  - `nr == 0` releases.
  - Error codes are documented only with the domctl (LSM-1, accepted).

## Considered, not edited

- The commit message does not mention the CHANGELOG entry:
  - Not required.

- `sizeof(*claims) * nr` is not checked for overflow:
  - Xen rejects counts above `MAX_NUMNODES + 1` with E2BIG before it reads the buffer,
  - and the neighbouring wrappers use the same pattern.
  - Not a defect for valid calls.
