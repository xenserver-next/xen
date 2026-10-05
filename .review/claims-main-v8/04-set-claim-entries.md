# 03 - xen/mm: add domain_set_claim_entries() for NUMA memory claims

**Result:** no change needed.

## Code review

- `domain_set_claim_entries()` takes `page_alloc_lock`, validates, allocates
  the array if node entries exist, installs under `heap_lock`, unlocks and
  then calls `xvfree()` on whatever array is left in `new_claims`. The lock
  order `page_alloc_lock` -> `heap_lock` is the same as in
  `domain_set_outstanding_pages()`, and nothing is freed under a lock.
- Validation is complete and cannot overflow. Every entry must have nonzero
  pages and zero `pad`, and `target_pages > d->max_pages - request->total` is
  rejected, so `total` stays at most `max_pages` and the subtraction cannot
  wrap. Duplicate HOST or node targets and reserved targets with bit 31 set
  return -EINVAL, offline or out-of-range nodes -ENOENT (the range test
  comes first, so `node_online()` never sees an index above MAX_NUMNODES).
  The final test keeps `tot_pages + total` within `max_pages`.
- `check_memory_for_claim_request()` tests `total` alone before the sum with
  `outstanding_claims`, so the sum cannot wrap. The per-node sum is 64-bit
  (`pages` is `uint64_aligned_t`). The domain has no outstanding pages at
  this point (checked right before), so it holds no claim on any node that
  would have to be subtracted.
- `domain_install_claims()` stores `unsigned int` values after validation
  bounded them by `max_pages` (an `unsigned int`), so nothing truncates.
  The comment "Without outstanding claims, a previous array only holds
  zeros." is correct: `d->outstanding_pages == 0` implies `d->node_claims ==
  0`, and the sum of `d->claims[]` equals `d->node_claims`. A host-wide-only
  request has `new_claims == NULL` and the old array is handed back for
  freeing. On failure `*claims` is untouched, so the caller frees the unused
  new array. The ownership comment above the function describes this and
  stays.
- The structure `xen_domctl_memory_claim` has no implicit padding (8 + 4 + 4
  bytes, `pad` checked), and `uint64_aligned_t` keeps the layout equal for
  32-bit and 64-bit callers.
- The function has no caller until patch 4. That is expected and the Notes
  say so; nothing can leak or misbehave in this tree. The release of
  `d->claims` that this patch's allocation requires is done by patch 4.
- Mechanics: subject 61 columns, body and Notes within 75, no trailing
  whitespace or tabs, new code within 79 columns, tag order correct.

## Edits applied

None.

## Considered, not edited

- Forward reference: the Notes say "This patch and the next one form one
  logical change". It is below `---`, so it is reviewer-facing text and not
  part of the commit; the code-review rules only forbid such references in
  the commit message body.
- `Notes:` come before `Changes in v8:` here, but after it in patch 1. Both
  are below `---`; no rule, no benefit from reordering.
- The comments "Test the total on its own first, the sum below can wrap on
  32-bit." and "Bit 31 marks special targets, only HOST is defined so far."
  are comma splices. They are readable and correct. Taste.
- The comment "The sum request->total is bounded by max_pages" has no final
  period; CODING_STYLE does not require one.
- `ASSERT(request->nr_entries)`: a caller contract that patch 4 satisfies
  (zero entries releases the claims instead).

## Review-note remarks (`.github/review-notes`)

- SCE-3 names `check_available_claims()`, which does not exist. The function
  is `check_memory_for_claim_request()`.
