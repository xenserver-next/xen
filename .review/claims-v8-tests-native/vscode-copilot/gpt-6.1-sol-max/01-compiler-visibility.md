# Compiler visibility guard

## Explain the host-side visibility requirement

**The suspicion.** The subject-only message does not explain why the visibility pragma is restricted to `__XEN__`.

**Disposition.** Hypervisor flags define `__XEN__`, preserving hidden visibility.
Host-side inclusions must not change the visibility of subsequently included system declarations.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -2,0 +3,4 @@
+Keep hidden visibility for the hypervisor, but do not impose it on
+host-side users of Xen headers. Declarations from subsequently included
+system headers must retain their normal visibility.
+
```
