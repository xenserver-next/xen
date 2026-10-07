# 04 - xen/mm: add domain_set_claim_entries() for NUMA memory claims

**Result:** the code is correct. Wording changes applied to the commit
message and to the notes below `---`.

## Code review

- Locking: `domain_set_claim_entries()` takes `d->page_alloc_lock`, which
  protects `d->max_pages` (`XEN_DOMCTL_max_mem` writes it under this lock)
  and `domain_tot_pages()`. Therefore the validation is still valid when
  `domain_install_claims()` takes `heap_lock`. The lock order is the same
  as in `domain_set_outstanding_pages()`. `get_free_buddy()` reads
  `d->claims` only under `heap_lock`, so swapping the pointer under
  `heap_lock` and freeing the old array after unlocking is safe.
- Validation cannot overflow. `target_pages > d->max_pages -
  request->total` keeps `total <= max_pages <= UINT_MAX`, so `total` fits
  in a 32-bit `unsigned long`, and `d->node_claims` and
  `d->outstanding_pages` (both `unsigned int`) do not truncate. The final
  test checks `tot_pages > max_pages` before the subtraction. `max_pages`
  can be below `tot_pages` after `XEN_DOMCTL_max_mem`.
- Targets: HOST twice, reserved bit-31 targets and duplicate nodes return
  -EINVAL. `target >= MAX_NUMNODES` is tested before `node_online()`.
  Online nodes without enough free memory fail with -ENOMEM in the memory
  check.
- `check_memory_for_claim_request()`: the first test is the wrap guard for
  32-bit, where `total` can be up to `UINT_MAX`. The comment says that.
  The per-node sum is `uint64_t`.
- `domain_install_claims()` updates all five counters (`d->outstanding_pages`,
  `d->node_claims`, `d->claims[]`, `outstanding_claims`,
  `node_claimed_pages[]`) under `heap_lock`. Every entry has nonzero pages,
  so `new_claims` is non-NULL whenever the loop writes through it. On
  failure nothing is modified and the unused array is freed.
- Rejecting a domain with outstanding claims returns -EINVAL, like the
  legacy "only one active claim per domain" path.
- `xvzalloc_array()` runs under `d->page_alloc_lock` with IRQs enabled.
  It may take `heap_lock` after `d->page_alloc_lock`, which is the
  established lock order.
- `page_alloc.c` gets `public/domctl.h` through `xen/sched.h`, which
  includes it directly. No include is missing.
- A non-static function without a caller builds without warnings, and its
  static helpers are used, so the patch is bisectable.
- To check at patch 5: the domctl must refuse dying domains under
  `domctl_lock`. `domain_kill()` releases the claims under that lock, and
  claims installed later would leak `outstanding_claims`. It must also
  bound `nr_entries` and copy the entries into a Xen buffer, because the
  helpers read `request->claim[i]` more than once.
- Mechanics: subject 61 characters, body within 72, no trailing
  whitespace, tags in order.

## Decisions

- "This patch and the next one form one logical change" is a forward
  reference, but it is below `---`.
  - Such reviewer-facing text does not end up in git,
    and on xen-devel it is the usual way to explain a split.
  - Earlier reviews agreed.

- domain_validate_claim_request() function header comment is:
  /* Validate a claim request and compute request->total and ->node_pages. */
  It names the out-fields that the code shows.
  It is one line that states the purpose and the side effect that the name "validate" does not show.
  - Keep it, a summary the effect of the function is perfect.
  - Update the skill to make such comments the ideal case.

- `nodemask_test()` + `node_set()` could be `node_test_and_set()`,
  which is one statement shorter but atomic on a local mask. Taste.
  - The author thinks that this is not taste because we don't want a global
    machine-wide sync because of a local operation
    - Or would the compiler optimize the atomic overhead away because it is local?

- Blank lines: the layout matches the author's style of patch 3
  (blank line after declarations and after `if` blocks).
  - Not changed, this appears to be the preferred Xen style for new code.
