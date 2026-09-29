---
type: but-branch-review
series: claims-v8/main
branch: claims-v8/main/libxc-get-memory-claims
reviews:
  - date: 2026-10-03T13:06:38+02:00
    model: Claude Sonnet 5.5
    harness: GitHub Copilot (VS Code, Xen Patch Reviewer and Improver)
    effort: high
    verdict: approve
findings:
  - id: LGM-10
    severity: info
    status: accepted
    title: Bounce size can wrap on 32-bit tools
  - id: LGM-11
    severity: nit
    status: fixed
    fixed_by: [sso]
    title: Header comment omits that *nr holds the count on ERANGE
  - id: LGM-12
    severity: info
    status: open
    title: No CHANGELOG.md entry for the new domctls and libxc wrappers
---
## LGM-10 (info, accepted): Bounce size
`sizeof(*claims) * *nr` wraps for `*nr >= 2^28` where `size_t` is 32 bits.
Xen clamps the capacity, but copies back as many entries as the domain has,
so a wrapped, tiny bounce buffer could be overrun by the copy-back.
Callers pass the capacity they allocated; the commit message already says
that wrappers do not check this, like the other wrappers in this file.

## LGM-11 (nit, fixed): Header comment omits that `*nr` holds the count on ERANGE

The comment said "Pass `*nr == 0` and `claims == NULL` to query the required
count; a too small buffer fails with `errno == ERANGE`". It does not say that
the count is delivered in `*nr` also on that failure, which is the whole
point of the query, and nothing about the buffer after a failure:
`xc_hypercall_bounce_post()` copies the complete `BOUNCE_OUT` buffer back
even if the domctl failed. Xen copies no entries on `-ERANGE`, and the
bounce buffer is zeroed on allocation, so `claims` is overwritten with
zeros, not with stale data.

Fix: `sso` (comment only).

## LGM-12 (info, open): No CHANGELOG.md entry

This stack adds `XEN_DOMCTL_set_memory_claims`, `XEN_DOMCTL_get_memory_claims`
and the two libxenctrl wrappers. `CHANGELOG.md` has an `### Added` section
under `4.23.0 UNRELEASED` that is empty. A short entry belongs to the
commit that completes the feature for users of the series (this or the
patch that follows with a libxenguest user), e.g.:

```
### Added
 - NUMA-aware memory claims: XEN_DOMCTL_set_memory_claims and
   XEN_DOMCTL_get_memory_claims, with libxenctrl wrappers.
```

Not edited: the entry is a decision of the author about where the series
announces the feature; the working tree also carries uncommitted
`CHANGELOG.md` edits that this review does not touch.

## Verified
The bounce size comes from the input `*nr`:
- A larger returned count on `-ERANGE` does not overflow the bounce
  copy-back: Xen copies no entries on error, and the bounce size was fixed
  at declaration from the input `*nr`, so the copy-back size cannot follow
  the returned count.
- `*nr == 0` with `claims == NULL` bounces nothing, as pre-bounce accepts a
  NULL user buffer.
- `*nr` is updated only after the domctl, and the bounce size was fixed at
  declaration, so the returned count does not change the copy-back size.
- `do_domctl()` copies the domctl back on failure too, so `*nr` carries the
  needed count after `ERANGE`.
- `*nr` keeps its input value for failures that do not reach the domctl
  handler's copy-back (for example `ESRCH`), as `domctl.u.memory_claims`
  is unchanged then.
- `tools/libs/ctrl/xc_domain.o` compiles with `-Werror` (result of the
  earlier build, not repeated for this review).
