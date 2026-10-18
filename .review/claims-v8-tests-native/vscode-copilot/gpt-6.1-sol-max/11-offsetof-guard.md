# Preserve an existing `offsetof`

## Explain the host-header dependency without changing Xen's fallback

**The suspicion.** The subject-only message does not explain the host-header conflict being avoided.

**Disposition.** A prior host definition must be preserved, while Xen retains its fallback when no definition exists.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -2,0 +3,3 @@
+Host standard headers may define offsetof before including Xen headers.
+Preserve that definition and retain Xen's builtin fallback otherwise.
+
```
