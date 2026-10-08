# 00 - Cover letter: xen/mm: introduce handling of multi-node NUMA claim sets

File `claims-main-v8.txt` from "Add claims-main-v8.txt" (`aaca411260`) with "fixup claims-main-v8.txt" (`9f9879b0f4`) applied. Reviewed last, after patches 1-8.

**Result:** consistent with the series. Grammar, typo and list-format fixes are applied to the working tree (unstaged), see `../opus/commits/00-cover-letter.md`. One optional suggestion below.

## Checked against the series

- "Patches 1-4 make no functional change until patch 5 adds the domctl":
  - patches 1-3 end with "No functional change: nothing installs ... claims yet",
  - and patch 4 adds `domain_set_claim_entries()` without a caller.

- "Allocates the d->claims[node] array on demand":
  - patch 4 allocates it with `xvzalloc_array()` in `domain_set_claim_entries()`;
  - patch 1 declares `d->claims` as a pointer.

- "removal of the capability for replacing claims":
  - patch 4 returns -EINVAL when the domain already has outstanding claims.

- "The host-wide XENMEM_claim_pages infrastructure is preserved and reused":
  - patch 5 releases claims with `domain_set_outstanding_pages(d, 0)`.

- "separate call graphs":
  - the set path (patches 4-6) and the get path (patches 7-8) share only the data structures.

- Not re-verified: "bisectable on x86_64, arm64, arm32 and riscv64":
  - This review did not run builds.

## Considered, not edited

- "Patches 2 and 3 are extracted and refactored, functionally equivalent." is terse:
  - The fixup dropped the earlier "but" on purpose,
  - and the sentence is clear enough.

- "Tested using extensive updated system and integration tests" is wordy but clear.
