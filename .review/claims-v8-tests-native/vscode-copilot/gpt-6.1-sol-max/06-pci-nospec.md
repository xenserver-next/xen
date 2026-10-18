# Direct PCI nospec dependency

## The include documents a direct dependency rather than a production build failure

**The suspicion.** The message could imply that this patch repairs a production undeclared-helper failure.

**Disposition.** `xen/spinlock.h` already supplies `xen/nospec.h` transitively.
The direct include instead makes `pci.h` independent of that transitive dependency for host consumers.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -2,0 +3,4 @@
+pci.h uses lock_evaluate_nospec() directly. Include its defining header
+rather than relying on spinlock.h to include it, so consumers can supply
+their own spinlock implementation without losing the nospec declaration.
+
```
