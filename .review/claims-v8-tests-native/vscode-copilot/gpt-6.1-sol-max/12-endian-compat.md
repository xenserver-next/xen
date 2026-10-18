# Libc-compatible endian constants

## Explain the limited purpose of the numeric values

**The suspicion.** The message can be read as establishing complete libc endian compatibility, although this patch only aligns macro replacement tokens.

**Disposition.** The values `1234` and `4321` match libc constants.
Host wrappers must still handle libc defining both names when importing presence-based Xen byte-order code.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -2,0 +3,5 @@
+Use the conventional numeric values for Xen's active-endian constants
+so including libc headers does not redefine them with different tokens.
+This preserves Xen's endian selection; host wrappers must also account
+for libc defining both endian names when including presence-based code.
+
```
