# 04 - xen/domctl: add XEN_DOMCTL_set_memory_claims

Commit `6bf2b0480e` (`8a700327b4` before the rebase over the reworded
patches 1 and 2; message and tree unchanged).

**Result:** no change needed.

## Code review

- `set_memory_claims()` checks in this order: `pad` (EINVAL), release when
  `nr_entries == 0`, LLC coloring (EOPNOTSUPP), dying domain (ESRCH),
  `nr_entries > MAX_NUMNODES + 1` (E2BIG), domain not paused (EBUSY), then
  buffer allocation (ENOMEM), `copy_from_guest()` (EFAULT) and
  `domain_set_claim_entries()` (EINVAL, ENOENT, ENOMEM). The errno list in
  the `domctl.h` comment matches the code one by one, including "fails
  without changing the claims".
- The release path is deliberately ahead of the state checks, so a release
  works for a dying or running domain, as the commit message says. It calls
  `domain_set_outstanding_pages(d, 0)`.
- The domctl differs from `XENMEM_claim_pages` in two documented ways: it
  requires the domain to be paused (new; the commit message explains why and
  SCE-1 covers the race it closes), and a dying domain returns ESRCH for
  installs instead of EINVAL. LLC coloring is rejected like
  `XENMEM_claim_pages` does. Pause state and `is_dying` cannot change while
  the handler runs: `XEN_DOMCTL_destroydomain`, `pausedomain` and
  `unpausedomain` need the domctl lock, which `do_domctl()` holds around this
  case. A domain created by `XEN_DOMCTL_createdomain` starts with
  `controller_pause_count == 1`, so the build use case passes the check.
- `domain_set_outstanding_pages(d, 0)` now also releases node claims
  (`domain_reduce_node_claims(d, d->node_claims)`) and detaches `d->claims`.
  The array is freed with `xvfree()` after both locks are dropped. The same
  path serves `domain_kill()` (`domain.c`) and `XENMEM_claim_pages` with 0
  pages, so the array allocated by patch 3 cannot outlive the domain. This
  closes the open end of patch 3.
- `request` is zero-initialised, the buffer is freed on every path after the
  allocation, and `xvmalloc_array()` is overflow-safe. The count is capped at
  `MAX_NUMNODES + 1` before the allocation.
- FLASK: `flask_claim_pages(d)` (defined earlier in `hooks.c`) gives the
  same `setclaim` check as `XENMEM_claim_pages`, and the comment in
  `access_vectors` is updated. Without FLASK, `xsm_domctl()` defaults to
  `XSM_PRIV`, as for `xsm_claim_pages(XSM_PRIV, d)`.
- Public header: `xen_domctl_memory_claims` has no implicit padding (8 + 4 + 4
  bytes), `pad` is checked, the handle type is defined with
  `DEFINE_XEN_GUEST_HANDLE()`, and the command number 91 follows 90. The
  interface version stays: the comment at the top of `domctl.h` says pure
  additions (new sub-commands) do not need a bump.
- Includes are present (`<xen/llc-coloring.h>`, `<xen/xvmalloc.h>` in
  `domctl.c`).
- Mechanics: subject 44 columns, body and Notes within 75, no trailing
  whitespace or tabs, longest new code line is 79 columns, tag order correct.

## Edits applied

None.

## Considered, not edited

- The local `claim` in `set_memory_claims()` could be `request.claim`. It is
  a matter of taste and not wrong.
- `claim_set.claim` is not const although `set_memory_claims()` only reads
  through it: the struct is shared with the get operation (see SCE-3).
- "Keep domain_set_outstanding_pages() until a later patch series." in the
  Changes list is terse, but it is below `---` and understandable in the
  context of the cover letter.
