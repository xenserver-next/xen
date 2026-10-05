# 08 - libxc: add xc_domain_get_memory_claims()

Commit `f921adbe80` (`72f10a39ab` before the rebase; message and tree
unchanged).

**Result:** no change needed.

## Code review

- The OUT bounce buffer is sized from the input capacity. After the domctl,
  `HYPERCALL_BOUNCE_SET_SIZE()` limits the copy back to the returned entries,
  or to none on failure, so `claims` is untouched on ENOBUFS. The buffer is
  freed by its stored page count, so shrinking the size is safe.
- `do_domctl()` copies the domctl back even on failure, and Xen sets
  `copyback` for ENOBUFS, so `*nr` holds the needed count. On other errors,
  Xen does not copy back and `*nr` keeps the input value.
- `*nr == 0` with `claims == NULL` skips the bounce buffer and works as a
  count query.
- Mechanics: within limits, no trailing whitespace, tags in order.

## Considered, not edited

- In the `xenctrl.h` comment, the second bullet under "fail with errno
  ENOBUFS:" is a usage hint, not a consequence. An earlier review settled
  this wording, so it stays.
