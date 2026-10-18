# Seqcount processor dependency

## Explain the direct processor-header dependency

**The suspicion.** The subject-only message does not explain why the seqcount header needs the architecture processor header.

**Disposition.** The seqcount reader calls `cpu_relax()`, whose definition comes from the architecture processor header.
The message should explain that direct dependency rather than relying on the caller's include order.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -2,0 +3,3 @@
+The seqcount reader calls cpu_relax(). Include its architecture definition
+directly instead of depending on the caller's preceding includes.
+
```
