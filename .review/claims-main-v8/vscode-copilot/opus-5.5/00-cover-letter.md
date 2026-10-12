# 00 - Cover letter: xen/mm: introduce per-node NUMA memory claims

**Result:** the cover letter describes the current eight-patch series.

- The interface list matches patches 5 to 8.
- Patches 1 to 4 have no functional effect until patch 5 adds the set domctl.
- Patch 3 capitalises the retained redemption-count comment.
- Patch 4 compares outstanding claims with the remaining free pages,
  avoiding an addition-overflow dependency.
- Patch 5 documents builder-side serialization. Pausing prevents
  guest-initiated allocations, not allocations by another builder thread.
- Patch 7 documents the shared request's get-side count and set-only sums.
- The per-patch review notes are separate review metadata, not part of the eight-patch submission.
- The builder-allocation window and memory-offlining limitations remain
  the accepted scope constraints in SCE-1/SCE-2.

## Validation

Compile tests were not rerun. The whitespace checks passed.

The availability predicate was checked with Python integers as an
arbitrary-precision oracle. For each width (32 and 64 bits), the model used
six boundary values: 0, 1, half the unsigned maximum, half plus 1,
maximum minus 1, and maximum. All 6^3 = 216 triples were checked, followed
by 10,000 random triples using a generator seeded with 0.

Thus 2 * (216 + 10,000) = 20,432 comparisons matched the mathematical
rejection condition `request + outstanding > available`. The model
short-circuits when `request > available`, so subtraction is performed
only when it cannot underflow. Full-width values stress the arithmetic;
some exceed the actual request limits.

A separate 32-bit counterexample reproduced the old addition wrapping:
available = 0xf0000000, outstanding = 0xe0000000, request = 0x30000000.
The old unsigned sum wraps to 0x10000000 and accepts; the current
comparison rejects. These are arithmetic-model checks, not execution of
the C function, Xen runtime tests, or proof that the counterexample is
reachable on supported hardware.

## Review cycle: 2026-10-12

- Scope:
  - Reviewed the eight code patches in chronological order and compared the corresponding reports from the other models.
  - No new functional blocker was found within the documented builder-serialization and memory-offlining constraints.
  - Patch 5 still needs the reviewer-facing wording clarification recorded in its notes.

- Review metadata corrections:
  - The reports are separate metadata, not included in the submitted code patches.
  - Removed unsupported nodemask timing and bounce-page safety claims.
  - Distinguished libxc bounce allocation failure from Xen claim-availability failure.
  - Removed the obsolete statement that patch 6's message does not mention its changelog entry.
  - Updated the historical wrapper-documentation finding to reflect the documented pause requirement.

- Non-build validation:
  - All eight code patches and the tracked review edits pass `git diff --check`.
  - An exhaustive mathematical redemption model passed 52,500 cases: three nodes with claims of 0 to 4 pages, a host-wide claim of 0 to 4 pages, allocation sizes of 0 to 20 pages, and allocation from each claimed node or a fourth unclaimed node.
  - The model checked full redemption, nonnegative counters, the cached node sum, the remaining host-wide claim, and preservation of other domains' global claims.
  - The availability predicate matched an arbitrary-precision oracle for 432 boundary triples across 32- and 64-bit widths.
  - These checks model the reviewed arithmetic; they do not execute the C implementation.
  - Compile tests and Xen runtime tests were not rerun.
