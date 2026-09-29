---
type: but-branch-review
series: claims-v8/main
branch: claims-v8/main/libxc-set-memory-claims
reviews:
  - date: 2026-10-03T13:06:38+02:00
    model: Claude Sonnet 5.5
    harness: GitHub Copilot (VS Code, Xen Patch Reviewer and Improver)
    effort: high
    verdict: approve
findings:
  - id: LSM-1
    severity: nit
    status: accepted
    fixed_by: [ywu]
    title: Header comment omits the target meaning and the EBUSY failure
---

# Review: claims-v8/main/libxc-set-memory-claims

## LSM-1 (nit, accepted): Header comment omits the target meaning and EBUSY

The only documentation for toolstack callers is the comment in
`tools/include/xenctrl.h`. It said nothing about how an entry selects a node
or the host-wide claim (`target`, `XEN_DOMCTL_CLAIM_MEMORY_HOST`), and nothing
about the new restriction that makes the call fail with `EBUSY` on a domain
that is not paused. A caller finds out only by reading the hypervisor.

Autor comment:
- This would duplicate the information on error codes in domctl.h.
- duplicate information can become stale and should be avoided.
- Toolstack developers are expected to read the actual hypercall in domctl.h
- domctl wrapper documentation only needs to document the wrapper itself.

## Verified (only entries not already in the commit message)
- `DECLARE_HYPERCALL_BOUNCE_IN()` casts away `const`, so the const `claims`
  parameter works; `tools/libs/ctrl/xc_domain.o` compiles with `-Werror`.
- `nr == 0` with `claims == NULL` bounces nothing, and the domctl handler
  returns before touching the handle.
- A `nr` above `MAX_NUMNODES + 1` makes the domctl fail with `-E2BIG` before
  any guest memory is read, so a wrapped `sizeof(*claims) * nr` on 32-bit
  tools cannot lead to an out-of-bounds read by Xen.
- The wrapper follows the bounce pre, domctl, bounce post pattern and
  releases the bounce on every path after a successful pre.
- `xc_hypercall_bounce_pre()` returns 0 without a bounce for `claims == NULL`,
  so `nr == 0` needs no special case, and for `nr == 0` with a non-NULL
  `claims`, Xen does not touch the guest handle.
- `-1` with `errno` set is returned for a failed pre, as in the neighbouring
  wrappers; the domctl failure codes pass through `do_domctl()`.
