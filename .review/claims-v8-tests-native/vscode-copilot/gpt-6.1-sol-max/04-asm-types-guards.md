# Architecture and common type guards

## Explain which typedefs remain private to Xen

**The suspicion.** The message omits the signed host `register_t` collision and incorrectly locates the `ssize_t` guard in architecture headers.

**Disposition.** ARM and RISC-V use unsigned `register_t`, unlike libc.
The `ssize_t` guard is in the common header.
These compatibility prerequisites belong before the existing NUMA test conversion.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -1 +1 @@
-*/asm/types.h: Guard typedef register_t/ssize_t with ifdef __XEN__
+xen/types: Keep private register_t and ssize_t typedefs in Xen
@@ -2,0 +3,5 @@
+Host libc headers provide register_t and ssize_t. In particular, libc's
+signed register_t conflicts with Xen's unsigned ARM and RISC-V typedefs.
+Keep those architecture typedefs and the common ssize_t typedef for Xen
+builds, and let host-side header users use their libc definitions.
+
```
