# Generated configuration guard

## Name the changed header and explain the guard

**The suspicion.** The subject names `xen/compiler.h`, but this patch changes `xen/kconfig.h` and omits the reason for the guard.

**Disposition.** Hypervisor flags retain the generated configuration.
Host-side consumers supply their own configuration definitions.
The message should name the changed header.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -1 +1 @@
-xen/compiler.h: Guard including generated/autoconf.h with ifdef __XEN__
+xen/kconfig.h: Restrict generated configuration to Xen builds
@@ -2,0 +3,4 @@
+Host-side users of Xen headers provide their own configuration defines.
+Do not require a generated hypervisor configuration for those users;
+keep including it for Xen builds.
+
```
