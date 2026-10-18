# Private CPU register guard

## Explain the private and public layouts

**The suspicion.** The subject-only message does not explain why the private register layout must be excluded from host-side consumers.

**Disposition.** The public header defines `cpu_user_regs` for host users and renames it to `guest_user_regs` inside Xen.
The private layout belongs to the hypervisor;
the two layouts are not interchangeable.

**Targeted mitigation.** Clarify the commit message with the following proposed diff.

```diff
--- a/commit-message
+++ b/commit-message
@@ -2,0 +3,5 @@
+Host tools use the public cpu_user_regs layout. Defining Xen's private
+layout as well conflicts with that definition. Keep the private layout
+for Xen and include the public definition for host users, including the
+MSR helpers and the register frame embedded by asm/current.h.
+
```
