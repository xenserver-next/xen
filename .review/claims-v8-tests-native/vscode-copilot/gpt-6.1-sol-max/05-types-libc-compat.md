# Integer limit macro compatibility

## Describe the actual limit-macro change

**The suspicion.** The subject names nonexistent `limit.h` and suggests a broader type change, although this patch only guards integer limit macros.

**Disposition.** Hypervisor limit definitions remain under `__XEN__`.
Host consumers include their standard headers when they need limits and format macros.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -1 +1 @@
-xen/types.h: Fix conflict with other inttypes.h and limit.h headers
+xen/types.h: Keep integer limit macros private to Xen
@@ -2,0 +3,5 @@
+The standard limits.h and stdint.h headers provide integer limit macros
+for host-side users. Avoid redefining those macros in Xen headers when
+building outside the hypervisor. Xen builds retain the existing limits;
+host consumers include their standard headers when they need them.
+
```
