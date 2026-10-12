# 08 - libxc: add xc_domain_get_memory_claims()

**Result:** no open findings.
- The output bounce copies back only returned entries on success and
  nothing on failure.
- Success and ENOBUFS return the count; other errors preserve the input
  count because Xen does not copy back the domctl.
- NULL with count zero is the documented count query. A NULL/nonzero
  buffer is caller misuse that Xen rejects when entries need copying;
  no extra client-side validation is required.
- A zero-count guest copy does not access the guest buffer.
- The copy-back comment already excludes ENOBUFS.
- The changelog's "reads them" refers to the preceding claims entry.
