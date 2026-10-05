# 05 - xen/domctl: add XEN_DOMCTL_set_memory_claims

**Result:** no change needed.

## Code review

- `set_memory_claims()` checks `pad` (EINVAL), releases on
  `nr_entries == 0`, then rejects LLC coloring (EOPNOTSUPP, as
  `XENMEM_claim_pages` does), a dying domain (ESRCH), too many entries
  (E2BIG) and a domain not paused by the controller (EBUSY) before it
  allocates and copies the array. The errno list in `domctl.h` matches.
- The checks are reliable under the domctl lock: `domain_kill()` is only
  called from `XEN_DOMCTL_destroydomain`, and pause and unpause are domctls
  as well. `domain_create()` sets `controller_pause_count = 1`, so the build
  use case passes.
- FLASK: `flask_claim_pages(d)` gives the `setclaim` check of
  `XENMEM_claim_pages`; without FLASK, `xsm_domctl()` defaults to
  `XSM_PRIV`.
- Public header: no implicit padding (8 + 4 + 4 bytes), command 91 follows
  90, and pure additions need no interface-version bump.
- Mechanics: within limits, no trailing whitespace, tags in order.
