# 07 - xen/domctl: add XEN_DOMCTL_get_memory_claims

**Result:** the code is correct. 

## Code review

- Dispatch: the case is in the `switch` after `xsm_domctl(XSM_PRIV, d, op)`
  and before `domctl_lock_acquire()`, next to `XEN_DOMCTL_getvcpuinfo`, as
  the message says. `d` comes from `rcu_lock_domain_by_id()`, so it is
  never NULL and never a system domain. The case ends with
  `goto domctl_out_unlock_rcuonly`, which drops the RCU lock and copies the
  domctl back if `copyback` is set.
- Locking: every writer of `d->outstanding_pages`, `d->node_claims` and
  `d->claims[]` holds `heap_lock`. Installing (patch 4) and redeeming
  (patch 3) update them together, and the release (patch 2) detaches
  `d->claims` under `heap_lock` and frees it after unlocking. A reader
  under `heap_lock` therefore sees a consistent set, and `d` stays valid
  while it is RCU-locked. The op needs no domctl lock, even while
  `domain_kill()` releases the claims.
- `get_memory_claims()`: a nonzero `pad` fails before `copyback` is set.
  The capacity is clamped to `MAX_NUMNODES + 1`, which is never below the
  number of entries (at most one per online node plus the host-wide one),
  so the clamp cannot cause ENOBUFS. A capacity of 0 gets `ZERO_BLOCK_PTR`
  from `xvmalloc_array()`, which `xvfree()` accepts. `copyback` is set on
  success, ENOBUFS and EFAULT, so the caller always gets the count.
  `copy_to_guest()` copies only on success and only the entries filled.
- `domain_get_claim_entries()`: each entry is a compound literal, so `pad`
  is zero and no stale heap data reaches the guest. On ENOBUFS it fills the
  first `max_entries` entries of the Xen buffer, which the caller does not
  copy, so "no entries are written" in `domctl.h` holds for the guest.
  `for_each_online_node()` matches the install check (`node_online()`) and
  the loop of patch 3. The comment is three lines and states the in/out
  use of `nr_entries` and the ENOBUFS return; it stays (no churn).
- `domctl.h`: the errno list (EINVAL, ENOMEM, ENOBUFS, EFAULT) matches the
  code, in the order of the checks. The field comments describe both ops,
  and "OUT: number of entries needed" matches the code. Command 92 follows
  91. `mm.h` wraps the prototype, which would be 80 columns on one line.
- FLASK: `getdomaininfo`, with the `access_vectors` comment updated. dom0
  already has `getdomaininfo` for all domains, so no policy change is
  needed. The dummy XSM falls back to `XSM_PRIV`.
- Mechanics: subject 44 characters, body within 72, `git show --check`
  clean, tags in order.

## Considered, not edited

- ESRCH (the domain does not exist) is not in the get errno list, while the
  set list names it together with the dying case, which is specific to set.
  - Every domctl that takes a domain can fail with ESRCH or EPERM, so
    the get list is not misleading.

- The FLASK case could call `flask_getdomaininfo(d)`, as the set case
  calls `flask_claim_pages(d)`. The neighbouring cases call
  `current_has_perm()` directly, which shows the permission. Taste.

- "On output, it is the number of entries of the domain" in `domctl.h` is
  loose but clear from the context.

- "Use xvmalloc_array() as the buffer ..." below `---` says "because" in
  patch 5. Both are correct English.

## Decisions

- Use ENOBUFS for a too-small buffer, like `XEN_DOMCTL_get_vcpu_msrs`,
  `XENMEM_get_vnumainfo` and hypfs. Only
  `XENMEM_reserved_device_memory_map` uses ERANGE, which Xen's
  `public/errno.h` describes as "Math result not representable".
- `host_claims` is now `host_claim`: a domain has one host-wide claim, and
  `domain_redeem_host_claim()` (patch 3) uses the same name.

## Not considered relevant

- The compound literals list `.target` before `.pages`, unlike the struct
  declaration. C allows any order. Taste.

- No test exercises the new domctls:
  - (`tools/tests/mem-claim` covers only `XENMEM_claim_pages`).
  - That is not necessarily a defect of this patch, it is a minimum viable product only.
  - Intentionally and announced in the cover letter, the tests are separate.
    - A comprehensive test that covers the new API completely need many tests cases.
      - To not duplicate a lot of setup and teardown code as well as common calls,
        the tests need a common test framework that provides those features.
    - The submission of system test and native test is announced in the cover letter.
    - While a minimal test would be possible in this series, the next question would be:
