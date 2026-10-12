# 07 - xen/domctl: add XEN_DOMCTL_get_memory_claims

**Result:** the code is correct.

## Code review

- Dispatch:
  - the case is in the `switch` after `xsm_domctl(XSM_PRIV, d, op)` and before `domctl_lock_acquire()`,
  - next to `XEN_DOMCTL_getvcpuinfo`, as the message says.
  - `d` comes from `rcu_lock_domain_by_id()`:
    - so it is never NULL and never a system domain.
  - The case ends with `goto domctl_out_unlock_rcuonly`:
    - which drops the RCU lock,
    - and copies the domctl back if `copyback` is set.

- Locking:
  - every writer of `d->outstanding_pages`, `d->node_claims` and `d->claims[]` holds `heap_lock`.
  - Installing (patch 4) and redeeming (patch 3) update them together,
  - and the release (patch 2) detaches `d->claims` under `heap_lock` and frees it after unlocking.
  - A reader under `heap_lock` therefore sees a consistent set,
  - and `d` stays valid while it is RCU-locked.
  - The op needs no domctl lock, even while `domain_kill()` releases the claims.

- `get_memory_claims()`:
  - a nonzero `pad` returns EINVAL, without copy-back.
  - The capacity is clamped to `MAX_NUMNODES + 1`:
    - which is never below the number of entries (at most one per online node plus the host-wide one),
    - so the clamp cannot cause ENOBUFS.
  - A capacity of 0 gets `ZERO_BLOCK_PTR` from `xvmalloc_array()` (and from `xvzalloc_array()`), which `xvfree()` accepts.
  - `do_domctl()` sets `copyback` on success and ENOBUFS, the two cases where `domctl.h` defines the output `nr_entries`.
  - `copy_to_guest()` copies only on success and only the entries filled.

- `domain_get_claim_entries()`:
  - each entry is a compound literal, so `pad` is zero and no stale heap data reaches the guest.
  - On ENOBUFS it fills the first `max_entries` entries of the Xen buffer:
    - which the caller does not copy,
    - so "no entries are written" in `domctl.h` holds for the guest.
  - `for_each_online_node()` matches the install check (`node_online()`) and the loop of patch 3.
  - The comment is three lines and states the in/out use of `nr_entries` and the ENOBUFS return:
    - it stays (no churn).

- `domctl.h`:
  - the errno list (EINVAL, ENOMEM, ENOBUFS, EFAULT) matches the code, in the order of the checks.
  - The field comments describe both ops,
  - and "OUT: number of entries needed" matches the code.
  - Command 92 follows 91.
  - `mm.h` wraps the prototype, which would be 80 columns on one line.
  - `claim_set` documents get-side capacity/count and set-only sums.

- FLASK:
  - `getdomaininfo`, with the `access_vectors` comment updated.
  - dom0 already has `getdomaininfo` for all domains, so no policy change is needed.
  - The dummy XSM falls back to `XSM_PRIV`.

## Considered, not edited

- ESRCH (the domain does not exist) is not in the get errno list:
  - while the set list names it together with the dying case, which is specific to set.
  - Every domctl that takes a domain can fail with ESRCH or EPERM, so the get list is not misleading.

- "On output, it is the number of entries of the domain" in `domctl.h` is loose but clear from the context.

- `copyback` is set by `do_domctl()` with `if ( !ret || ret == -ENOBUFS )` (done):
  - v8's helper serves only get, and every other single-op helper in `common/domctl.c` leaves `copyback` to `do_domctl()`.
  - The condition matches `domctl.h` and Jan's `XEN_SYSCTL_pm_op` copy-back on -EAGAIN.
  - Only the pointless copy-back on EFAULT goes away, so no revlog bullet and no comment are needed.

- Use `xvzalloc_array()` for the get buffer:
  - Explained below `---` in the commit message:
    - Use xvzalloc_array(), as the buffer is copied out and need not be
      physically contiguous.
  - It zeroes the entire copy-out buffer, not just what the called function would write to.
  - Jan asked for it in v7.
  - The buffer is filled in another file, so zeroing guards against future changes.
  - Not zeroing would only be an option if fully redundant locally by being fully overwritten in the same function.

- A dedicated FLASK permission instead of `getdomaininfo` is a policy question for the FLASK maintainer:
  - not a defect.

## Decisions

- Use ENOBUFS for a too-small buffer:
  - like `XEN_DOMCTL_get_vcpu_msrs`, `XENMEM_get_vnumainfo` and hypfs.
  - Only `XENMEM_reserved_device_memory_map` uses ERANGE:
    - which Xen's `public/errno.h` describes as "Math result not representable".

- `host_claims` is now `host_claim`:
  - a domain has one host-wide claim,
  - and `domain_redeem_host_claim()` (patch 3) uses the same name.

## Not considered relevant

- The compound literals list `.target` before `.pages`, unlike the struct
  declaration. C allows any order. Taste.

- No test exercises the new domctls:
  - (`tools/tests/mem-claim` covers only `XENMEM_claim_pages`).
  - The cover letter announces a separate series for the updated system and integration tests.
  - Those tests are outside this branch and were not rerun in this review cycle.
  - Runtime coverage is therefore a verification dependency, not established by this source review.
