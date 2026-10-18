# Common NUMA node type

## Explain common NUMA type ownership

**The suspicion.** The message does not explain why `nodeid_t` belongs in the common header or how direct architecture-header users obtain it.

**Disposition.** The common header defines `nodeid_t` before including architecture NUMA declarations.
The x86 header obtains that common definition instead of maintaining a local typedef.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -1 +1 @@
-numa: Fix nodeid_t typedef and asm/numa.h inclusion
+numa: Define nodeid_t in the common header
@@ -2,0 +3,5 @@
+Define nodeid_t before including architecture NUMA declarations, so the
+type is also available to host-side users of the common header. Remove
+the x86-local typedef and make direct x86 architecture-header users obtain
+the common definition without depending on an earlier include.
+
```
