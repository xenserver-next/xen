---
type: but-branch-review
series: claims-v8/main
branch: claims-v8/main/domctl-get-memory-claims
reviews:
  - date: 2026-10-03T13:06:38+02:00
    model: Claude Sonnet 5.5
    harness: GitHub Copilot (VS Code, Xen Patch Reviewer and Improver)
    effort: high
    verdict: approve
findings:
  - id: DGC-1
    severity: nit
    status: fixed
    fixed_by: [qwo]
    title: Shared struct documentation and field comments in domctl.h
  - id: DGC-2
    severity: nit
    status: fixed
    fixed_by: [pzu]
    title: Commit message says the host-wide claim is "always" returned first
---

# Review: claims-v8/main/domctl-get-memory-claims

## DGC-1 (nit, fixed): Shared struct documentation and field comments

`struct xen_domctl_memory_claims` is now the argument of two domctls, but
nothing in front of it said so: the get documentation block sat directly on
top of the struct, as if it were the get argument only. The new field
comments also started with a lowercase `set:` / `get:`, while `CODING_STYLE`
wants multi-word comments to start with a capital letter, and squeezed
two roles and three directions into one line.

## DGC-2 (nit, fixed): "always returned first" in the commit message

The message of `323f3b08d2` says "The host-wide claim is always returned
first", which reads as if an entry is always present. The code (and the
public header) return it only if the domain has a host-wide claim. "for
toolstack queries and testing/inspection/verification" is also awkward, and
"returned together with the required number of entries" does not say that no
entries are copied on `-ERANGE`.

Fix: the empty fixup commit `pzu` carries the proposed replacement message
below a delimiter.

## Verified (only those not already added to the commit message)
- `do_domctl()` copies `op` back regardless of the return value when
  `copyback` is set, so the count reaches the caller on `-ERANGE`.
- `xvzalloc_array(..., 0)` for a count query returns a non-NULL zero-size
  pointer that `xvfree()` accepts, and `copy_to_guest()` with a count of 0
  succeeds.
- The compound literal assignments zero `pad`, and the buffer is zeroed
  anyway, so no uninitialized bytes reach the guest.
- `copy_to_guest()` copies `request.nr_entries` entries, which is at most the
  clamped capacity (`<= MAX_NUMNODES + 1`) that the temporary buffer was
  allocated for and at most the capacity the caller passed, so neither
  buffer is overrun. On `-ERANGE`, nothing is copied.
- `domain_get_claim_entries()` reads `d->outstanding_pages`, `d->node_claims`
  and `d->claims[]` under `heap_lock`, which protects all of them, and
  `for_each_online_node()` covers every node that can have a claim.
- The unbraced multi-line compound literal assignments under `if` are
  allowed by `CODING_STYLE` ("Braces should be omitted for blocks with a
  single statement").
- The access vector comment change is not parsed by `mkaccess_vector.sh`.
- Builds on x86_64, arm32 and arm64 with FLASK enabled (results of the
  earlier builds, not repeated for this review; the fixup of this review only
  changes comments).
