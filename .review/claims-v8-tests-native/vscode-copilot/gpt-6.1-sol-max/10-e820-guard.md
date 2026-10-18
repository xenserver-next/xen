# Private E820 declarations

## Identify the libxc conflict precisely

**The suspicion.** The phrase `public defs` does not identify the header that provides the conflicting E820 structure.

**Disposition.** The message should distinguish libxc declarations from the hypervisor public E820 header and explain why host users do not need the private helpers.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -1 +1 @@
-x86: Guard most of asm/e820.h, avoids conflicts with public defs
+x86/e820: Restrict private E820 declarations to Xen builds
@@ -2,0 +3,5 @@
+libxc's xenctrl.h declares its own struct e820entry. Host-side users
+including Xen's architecture headers must not also define the private
+hypervisor structure with the same tag. Keep the structures and helper
+declarations private to Xen, while retaining the common type constants.
+
```
