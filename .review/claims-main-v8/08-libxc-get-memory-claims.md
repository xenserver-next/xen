# 07 - libxc: add xc_domain_get_memory_claims()

**Result:** code and message correct. No edits.

## Code review

- The bounce buffer is `XC_HYPERCALL_BUFFER_BOUNCE_OUT`, so nothing is
  copied in. Its size, `sizeof(*claims) * *nr`, is evaluated at the
  declaration, so `nr` must not be NULL. The header documents `*nr` as
  in/out, which makes this the caller contract.
- `struct xen_domctl domctl = {}` zeroes `pad`, which P6 rejects when it is
  nonzero. `nr_entries` carries the capacity in and the needed count out.
- A NULL `claims` with `*nr == 0` queries the count.
  `xc__hypercall_bounce_pre()` does not bounce a NULL buffer, and
  `xc__hypercall_bounce_post()` returns early when `hbuf` is NULL.
- `*nr` is stored after `do_domctl()` whatever `ret` is. libxc's
  `do_domctl()` bounces the domctl in both directions, also when the
  hypercall fails, and Xen sets `copyback` also for -ENOBUFS (P6). So `*nr`
  holds the needed count on ENOBUFS, as the header says. When the call fails
  before the handler runs, `nr_entries` is unchanged and `*nr` keeps its
  input value.
- `HYPERCALL_BOUNCE_SET_SIZE(claims, ret ? 0 : sizeof(*claims) * *nr)`
  before `xc_hypercall_bounce_post()` copies back nothing on failure and
  only the returned entries on success. Without it, the whole capacity
  would be copied back from the bounce buffer, which `xencall` zero-fills.
  That would overwrite the caller's array beyond the returned entries and,
  on ENOBUFS, the whole array with zeros. Xen returns 0 only if the entries
  fit the capacity (P6), so the copy never exceeds the bounce buffer.
  Precedent for adjusting the size before the post call: the livepatch list
  code in `xc_misc.c` lines 932 to 936 ("Copy only up 'rc' of data").
- The comment above the prototype matches the behaviour: capacity in `*nr`,
  failure with ENOBUFS, the count query with `*nr == 0` and `claims == NULL`,
  and "claims is not modified" holds because of the size adjustment above.
- The prototype needs three lines: `uint32_t *nr, xen_domctl_memory_claim_t
  *claims);` on one line would be 81 columns. The definition has the same
  wrapping.
- Commit message:
  - The ENOBUFS sentence matches the code.
  - The "Changes in v8" list matches the diff:
    - split, renames, no mode argument copy back of returned entries only

## Edits applied

None.

## Considered, not edited

TODO/FIXME:

- The commit message does not mention the CHANGELOG entry. Not required.

## Notes

- Unchecked `sizeof(*claims) * *nr`: the set wrapper and the neighbouring
  wrappers do the same. The review note records it as accepted (LGM-10).
  A caller with a valid array cannot reach the 32-bit wrap.
- The comment's second bullet ("Pass `*nr == 0` and `claims == NULL` ...")
  describes a deliberate capacity of zero, not an accidental small one.
  Correct because a capacity of zero is too small for any domain with claims; for a domain without claims the call returns 0 and `*nr == 0`.
