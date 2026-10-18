# Existing NUMA tests use shared definitions

## The conversion must not precede its header prerequisites

**The suspicion.** This patch uses the real Xen header graph before the required host-header compatibility definitions are available.

**Disposition.** Its native configuration includes `stdlib.h` before `xen/compiler.h` without handling libc's differently defined `__nonnull`.
With `CONFIG_WERROR=y`, that macro-redefinition diagnostic is an error.
The native configuration compatibility handling is introduced only with the harness.
ARM's unsigned `register_t` also conflicts with libc for host consumers taking that header path.

**Targeted mitigation.** Place the host-header compatibility and native-configuration prerequisites before this conversion, or fold the required prerequisites into this patch.

## Correct the subject typo and describe the conversion

**The suspicion.** The subject misspells `definitions` and omits the rationale for replacing local NUMA type and bitmap approximations.

**Disposition.** The message should identify the shared definitions and their required host-side preparation.

**Targeted mitigation.** Use the following proposed message diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -1 +1 @@
-tools/tests/numa: Use common Xen defines and nodemask defintions
+tools/tests/numa: Use common Xen defines and nodemask definitions
@@ -2,0 +3,5 @@
+Use Xen's typed MFNs, nodemasks and bitmap implementation instead of
+maintaining local approximations in the NUMA tests. Provide the host-side
+configuration and architecture shims needed by the shared definitions,
+and retain the existing test behavior on architectures with NUMA headers.
+
```
