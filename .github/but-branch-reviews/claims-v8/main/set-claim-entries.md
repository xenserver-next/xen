---
type: but-branch-review
series: claims-v8/main
branch: claims-v8/main/set-claim-entries
reviews:
  - date: 2026-10-03T13:06:38+02:00
    model: Claude Sonnet 5.5
    harness: GitHub Copilot (VS Code, Xen Patch Reviewer and Improver)
    effort: high
    verdict: approve-after-open-nits
findings:
  - id: DSM-1
    severity: info
    status: accepted
    title: No serialization against allocations
  - id: SCE-2
    severity: info
    status: accepted
    title: Memory offlining reducing free memory
  - id: SCE-5
    severity: info
    status: accepted
    title: 64-bit internal totals
  - id: SCE-6
    severity: nit
    status: fixed
    fixed_by: [qzo]
    title: Imprecise or missing comments in the new claim helpers
  - id: SCE-7
    severity: nit
    status: open
    title: struct claim_set and its prototype are not in the claim handling block of mm.h
  - id: SCE-8
    severity: nit
    status: open
    title: -ENOENT for out-of-range and undefined special targets
---
## DSM-1 (info, accepted): No serialization against allocations

The total pages of a domain could exceed the domain's `max_pages` limit
if an allocation is in-flight while staking claims.
- This is not new, `domain_set_outstanding_pages()` has the same window.
  Functions staking claims read `domain_tot_pages()` while an allocation
  can be between `alloc_heap_pages()` and `assign_pages()`
- Simply put, this is not supported: staking claims is supported for
  populating the guest memory using a single domain builder thread per
  domain only.
- To also make explicit that the domain is not supposed to be running when
  claims are made, the `domctl` requires the domain to be paused.

### Technical context

- When memory is assigned to a domain, `assign_pages()` updates
  `domain_tot_pages()` and checks it fits into `d->max_pages`,
- It does not include `d->outstanding_pages` in this calculation.
- In this case, an in-flight allocation could succeed while claims
are installed before `assign_pages()` takes `d->page_alloc_lock`
and updates `domain_tot_pages()`.

### Fix
- `assign_pages()` can be updated to check `d->outstanding_pages`.
- When it bails, the caller frees the allocated page and fail
  the allocation for the domain. This would need further review
  and should be submitted separately from NUMA claims support.

## SCE-2 (info, accepted): Memory offlining reducing free memory

While memory offlining can reduce the amount of free memory, which could cause
that the outstanding memory claims could exceed reduced free memory, this is
not seen as a problem this patch must address:

- The viewpoint of maintainers is that this is not a new problem (the existing
  domain_set_outstanding_pages() would suffer from it too) and that this should
  be sufficiently rare in the targeted servers in Xen production use that this
  is not seen as a problem for now.

- While there is a sysctl hypercall to offline memory, it is not a supported
  case we've to consider in this NUMA claims series. It can be fixed later.

## SCE-5 (info, accepted): 64-bit internal totals
- `struct claim_set` uses `uint64_t` for `total` and `node_pages`, which are
  bounded by `d->max_pages` (`unsigned int`). `CODING_STYLE` asks for fixed
  width types only for fixed width quantities; `unsigned long` fits.

Author's response:
- While the domain's d->max_pages is currently unsigned int, the plan is to
  widen all those types to unsigned long so lift the 16TB memory limit of these,
  so the public and the new internal types already use the widest types needed.

## SCE-6 (nit, fixed): Imprecise or missing comments in the new claim helpers

- The comment of `domain_install_claims()` said that `new_claims` is a zeroed
  array "if `d->claims` is NULL". `domain_set_claim_entries()` allocates it
  only if the request also has node-specific entries, and passes NULL for a
  host-wide-only request even when `d->claims` is NULL. Reworded.
- `domain_check_claim_request()` computes `request->total` and
  `request->node_pages` as a side effect; its comment only said "validate".
- `domain_set_claim_entries()` had a one-line comment without the locking
  contract (it takes `d->page_alloc_lock` non-recursively, so a caller must
  not hold it) and without the failure semantics.
- A trailing comment on the `if ( nodemask_test(...) )` line, and
  `node_set()` squeezed against the `return`. The comment is on its own
  line now, with a blank line before `node_set()`.

Fix: `qzo` (comments only, no code change).

## SCE-7 (nit, open): `struct claim_set` is not in the claim handling block

`xen/include/xen/mm.h` has a `/* Claim handling */` block with
`domain_adjust_tot_pages()`, `domain_set_outstanding_pages()` and
`get_outstanding_claims()`. `struct claim_set` and the prototype of
`domain_set_claim_entries()` are instead inserted at the top of the file,
between `struct page_info;` and `extern bool using_static_heap;`, away from
their siblings. They want to move into that block, behind
`domain_set_outstanding_pages()`.

Not edited: `domctl-get-memory-claims` adds the prototype of
`domain_get_claim_entries()` directly below the current location, so moving
the lines here makes that commit conflict. To be done on the next respin.

## SCE-8 (nit, open): -ENOENT for out-of-range and undefined special targets

`domain_check_claim_request()` returns `-ENOENT` for any `target >=
MAX_NUMNODES` that is not `XEN_DOMCTL_CLAIM_MEMORY_HOST`. This includes
undefined values with bit 31 set, which are not "a node that does not exist"
but invalid arguments, for which `-EINVAL` would be the better fit. The public
header documents ENOENT as "a node that does not exist or is offline", so
the series is self-consistent, and a toolstack can only hit this by passing an
invalid constant. Reconsider on the next respin, together with the header.

## Verified
- Failed requests leave the claims unchanged: all checks run before any
  state is modified, and the new array is freed on every failure path.
- Allocation and free of `d->claims` happen outside `heap_lock`; the
  allocation happens under `page_alloc_lock`, which matches the locking
  order (`page_alloc_lock` then `heap_lock`), and the 256-byte array comes
  from the xmalloc pool.
- `domain_set_outstanding_pages(d, 0)` detaches `d->claims` under both locks
  and frees it after releasing them.
- `claims[target]` is zero before it is set: all earlier claims are released
  first, and duplicate targets are rejected.
- `d->claims` is only dereferenced after checking `d->node_claims` or the
  pointer; the array is `MAX_NUMNODES` long and `target` is checked against it.
- Sums are bounded by `d->max_pages`, so no `unsigned int` overflow of
  `d->outstanding_pages`, `d->node_claims` or `claims[target]`.
- A new array is only allocated when the request has node-specific entries,
  so `node_claims` is non-zero at the end and the ownership transfer is
  reached.
- XENMEM_claim_pages with a non-zero count still fails with `-EINVAL` while
  node claims exist, as `d->outstanding_pages` is non-zero.
- `domain_check_claim_request()`: `total <= max_pages` holds before every
  iteration (it starts at 0 and `target_pages <= max_pages - total` is
  checked before the addition), so neither the subtraction nor the
  `uint64_t` sums wrap, and the later narrowing to `d->node_claims`,
  `d->outstanding_pages` and `array[target]` is lossless.
- A request with `nr_entries != 0` always has `total != 0` (zero-page entries
  are rejected), so the "releasing is always allowed" early return only
  applies to the empty request.
- `check_available_claims()`: the existing claim of the domain is added back
  for both the total and the per-node check, so replacing a claim by an
  equal or smaller one cannot fail with `-ENOMEM`. Host-wide claims stay
  satisfiable after the replacement: free memory minus all node claims is
  at least the sum of the host-wide claims, as `total_avail_pages >=
  outstanding_claims` is maintained.
- `domain_install_claims()` attaches `new_claims` exactly when the request
  has node entries and `d->claims` was NULL, and frees `d->claims` exactly
  when the request has none: no leak and no use after free in the four
  combinations. `xvzalloc_array()` of `MAX_NUMNODES` (at most 64) `unsigned
  int` is below `PAGE_SIZE`, so it comes from the xmalloc pool, which may
  take `heap_lock` only after `page_alloc_lock`, the established order.
- `xvfree()` runs after both locks are dropped in both callers, and accepts
  NULL.
- Builds without warnings on x86_64 (FLASK enabled), arm32 and arm64; the
  native claim tests (`make -C tools/tests/claims run`) pass (results of the
  earlier runs, not repeated for this review).
