# Reviewer trains of thought: likely false-alarm paths

These are spots where a careful reviewer reading the series top to bottom is
likely to *suspect a defect*, spend time, and conclude the code is correct.

Each entry records the suspicion, why the code is in fact correct, and a
targeted mitigation (code comment, commit message, or cover letter) that
would stop the reviewer going down the path in the first place.

None of these is a bug. They are places to spend a sentence to save a
reviewer (and a v9 round-trip) time.

## 1. Minor: `check_low_mem_virq()` subtraction looks introduced here

`check_low_mem_virq()` computes `total_avail_pages - outstanding_claims`,
which can wrap when offlining has pushed claims above free memory.

**The suspicion.** It sits in the file this series edits and touches the
same counters, so a reviewer may attribute the potential underflow to the
series.

**Why it is correct (for this series).** The expression is pre-existing and
untouched; the series neither introduces nor worsens it. Patch 1 even adds
the clamp-at-zero pattern (`a > b ? a - b : 0`) for exactly this offlining
case in the code it does touch.

**Targeted mitigation.** None in this series. If asked, point out it is
pre-existing and out of scope; a separate cleanup could apply the same
clamp there.

check_low_mem_virq() is used to send VIRQ_ENOMEM to listeners of VIRQs, and
as claims make memory unavailable to allocations without sufficient claims,
it would have to be discussed if check_low_mem_virq() should be called when
staking claims and when offlining as both reduce the amount of available
memory. In any case, improving sending VIRQ_ENOMEM is a separate concern.
