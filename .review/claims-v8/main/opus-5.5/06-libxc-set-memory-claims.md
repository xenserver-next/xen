# 06 - libxc: add xc_domain_set_memory_claims()

Commit `289f2ac713` (`0764c388b4` before the rebase; message and tree unchanged).

**Result:** no change needed.

## Code review

- `DECLARE_HYPERCALL_BOUNCE_IN()` copies the array to a hypercall buffer;
  - `nr == 0` with `claims == NULL` skips the bounce and releases all claims.
  - Failures return -1 with errno set, like the neighbouring wrappers.

- The `xenctrl.h` comment matches the domctl:
  - no outstanding claims for an install,
  - at least one page per entry,
  - the host target,
  - and release on `nr == 0`.

- The CHANGELOG entry is under "Added" for 4.23.

## Considered, not edited

- "per-node" in the message:
  - patches 1-5 and 7 said "node-specific claims" or "node claims".
  - They were changed to "per-node claims" to match this patch, patch 8 and the cover letter.

- The one-line comment above the definition repeats the header comment:
  - It is short and harmless.
