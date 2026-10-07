# 00 - Cover letter: xen/mm: introduce per-node NUMA memory claims

**Result:** wording changes applied to the testing paragraph and the
changelog. After the re-check against the final series, a bullet about
the pause requirement of patch 5 was added.

## Code review

- The interface list matches patches 5 to 8.
- "Patches 1-4 have no functional effect until patch 5 adds the domctl."
  matches the message of patch 4 ("nothing calls
  domain_set_claim_entries() yet"). Patches 1 to 3 only act on per-node
  claims, which nothing can install before patch 5.
- The patch 4 bullets match the code: smaller functions,
  `xvzalloc_array()` only when `node_pages` is nonzero, and EINVAL if the
  domain already has outstanding claims.
- "bisectable on x86_64, arm64, arm32 and riscv64": nothing was built in
  this review cycle. Its tree changes are only comments and blank lines
  (`domctl.h` in patches 5 and 7, `xenctrl.h` in patch 6, `domctl.c` and
  `page_alloc.c` in patch 7), so they cannot affect the builds.
- Only line 37, the URL of the v7 submission, exceeds 72 columns.

## Considered, not edited

- ppc64 also builds the common code that the series changes. It was not
  build-tested, so the list of architectures stays.
  - ppc64 is not a currently working Xen architecture, so it is exlcuded.
- "installs a set of host-wide and per-node memory claims" describes the
  kinds of claims in the set. Patches 4 and 5 allow at most one host-wide
  entry, and the sentence does not say otherwise. The CHANGELOG.md entry
  uses the same pairing.
- A link to Roger's message would help reviewers find the context of the
  quote. Optional, it needs the URL of the message.

## Decisions

## Changes applied

```diff
@@ -28,8 +28,8 @@ The host-wide XENMEM_claim_pages infrastructure is preserved and reused.
 A later series can consolidate the implementations and deprecate
 XENMEM_claim_pages. Deferring that keeps this series focused.
 
-Tested using extensive updated system and integration tests
-for Xen memory claims, which will be submitted subsequently.
+Tested with extensive system and integration tests for Xen memory
+claims, updated from v7. They will be submitted as a separate series.
 
 The patches are bisectable on x86_64, arm64, arm32 and riscv64.
 
@@ -40,7 +40,7 @@ Changes in v8 (incorporating v7 review feedback):
 
 Overall changes:
 
-- Split the submission into smaller patches as requested by review.
+- Split the submission into smaller patches as requested in review.
 - Defer changes beyond the minimum viable product to a later series.
 - Name the feature "per-node NUMA memory claims" (v7: "NUMA-aware memory
   claim sets"), and use "per-node claims" instead of "node-specific
@@ -48,12 +48,15 @@ Overall changes:
 
 Patch-specific changes:
 
-- Patches 1-4 make no functional change until patch 5 adds the domctl.
+- Patches 1-4 have no functional effect until patch 5 adds the domctl.
 - Patch 1 is extracted mostly unchanged (and is used in XenServer 9).
-- Patches 2 and 3 are extracted and refactored, functionally equivalent.
+- Patches 2 and 3 are extracted and refactored, functionally equivalent
+  to v7.
 - Patch 4 is based on the v7 design, but has many significant changes:
-  - Code is refactored into smaller functions, improving code quality.
-  - Allocates the d->claims[node] array on demand, as suggested in review.
-  - Simplified by removal of the capability for replacing claims.
+  - Refactor the code into smaller functions, improving code quality.
+  - Allocate the d->claims[] array on demand, as suggested in review.
+  - Remove the capability to replace claims, simplifying the code.
 - Patches 5-8 split the interface into independent set and get call
-  graphs, based on v7 review.
+  graphs, based on the v7 review.
+- Patch 5 installs claims only while the domain is paused, so the
+  domain cannot allocate memory in parallel.
```
