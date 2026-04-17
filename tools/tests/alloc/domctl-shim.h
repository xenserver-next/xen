/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Minimal shim to include xen/common/domctl.c in host-side tests.
 *
 * This shim provides the minimal Xen definitions that domctl.c
 * needs to run in a host-side test environment.  It replaces a
 * minimal subset of the Xen environment that xen/common/domctl.c
 * interacts with with stubs so it can run in the test environment,
 * allowing test scenarios to verify the behavior of domctl.c.
 *
 * Copyright (C) 2026 Cloud Software Group
 */
#ifndef _TEST_ALLOC_DOMCTL_SHIM_
#define _TEST_ALLOC_DOMCTL_SHIM_

/*
 * Guard against language servers and linters picking up this header.
 *
 * This shim is intended to be used in test programs for testing
 * the code of xen/common/domctl.c in a host-side test environment,
 * and test programs need to define TEST_WRAP_XEN_COMMON_DOMCTL_C
 * to enable the definitions in this header.
 */
#ifndef TEST_WRAP_XEN_COMMON_DOMCTL_C
#warning "Include this header only in integration tests using domctl.c"
#else

/*
 * Inside the intended test context, provide stub definitions.
 *
 * Some functions need to use types defined in specific headers,
 * so we include them and define header guards to prevent unwanted
 * definitions from those headers that conflict with the test harness
 * or bring in Xen-internal structures that are already provided by
 * the natural C compiler defines, libc defines and stubs in this shim.
 */

/* Header guards for domain.h inclusion. */
#define __XEN_ERRNO_H__
#define __ASM_DOMAIN_H__
#define __RWLOCK_H__

/* Include xen/domain.h for types required by the stubs below. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <xen/domain.h>
#pragma GCC diagnostic pop

/* Header guards for xen/common/domctl.c inclusion. */
#define _ASM_HW_IRQ_H
#define _XEN_ASM_X86_P2M_H
#define __XEN_BITMAP_H
#define __X86_CURRENT_H__
#define __XEN_HYPERCALL_H__
#define __XSM_H__
#define __XEN_IOCAP_H__
#define __XEN_RCUPDATE_H
#define __XEN_PAGING_H__

/*
 * Use the real guest_access functions and provide stubs for
 * xen/asm-x86/guest_access.h's __raw_copy_{to,from}_guest() functions
 * which are used by the high-level copy_{to,from}_guest*() functions.
 */
#define __X86_UACCESS_H__
#define __ASM_X86_GUEST_ACCESS_H__
#define __raw_copy_from_guest(dst, src, n) (memcpy((dst), (src), (n)), 0)
#define __raw_copy_to_guest(dst, src, n) (memcpy((dst), (src), (n)), 0)
#define raw_copy_from_guest(dst, src, n) (memcpy((dst), (src), (n)), 0)
#define raw_copy_to_guest(dst, src, n) (memcpy((dst), (src), (n)), 0)

/* Guest-frame-number type used in getdomaininfo() */
typedef unsigned long gfn_t;
#define gfn_x(gfn)           ((unsigned long)(gfn))
#define mfn_to_gfn(d, mfn)   ((gfn_t)mfn_x(mfn))
#define virt_to_mfn(v)       ((unsigned long)(v))
#define SHARED_M2P(mfn)      false

/* bitmap_to/from_xenctl_bitmap are in xen/bitmap.h (blocked).
 * Stub them as no-ops; domctl.c uses them only for NUMA info export. */
#define bitmap_to_xenctl_bitmap(d, s, n) 0
#define xenctl_bitmap_to_bitmap(d, s, n) 0

/* Domain dying states (normally in xen/sched.h, blocked by __SCHED_H__) */
#define DOMDYING_alive 0U
#define DOMDYING_dying 1U
#define DOMDYING_dead  2U

/* Minimal vcpu_runstate_info needed by getdomaininfo() */
#define RUNSTATE_running 0
struct vcpu_runstate_info { uint64_t time[4]; };
#define vcpu_runstate_get(v, r) ((void)(v), memset((r), 0, sizeof(*(r))))

/* vcpu iteration: no vCPUs in the test context */
#define for_each_vcpu(d, v) for ( (v) = NULL; (v) != NULL; )

/* Domain predicates not derived from any included header */
#define is_hvm_domain(d) false
#define cpupool_get_id(d) 0

/* spin_trylock: in the test context all locks are always available */
#define spin_trylock(l) (spin_lock(l), true)

/* XSM hooks: permit all operations in the test context */
#define XSM_OTHER                         0
#define XSM_XS_PRIV                       0
#define XSM_HOOK                          0
#define XSM_PRIV                          0
#define xsm_security_domaininfo(d, info)  ((void)(d), (void)(info))
#define xsm_domctl(xsm, d, ...)           0
#define xsm_getdomaininfo(xsm, d)         0
#define xsm_irq_permission(xsm, d, ...)   0
#define xsm_iomem_permission(xsm, d, ...) 0
#define xsm_iomem_mapping(xsm, d, ...)    0
#define xsm_set_target(xsm, d, e)         0
#define xsm_claim_pages(xsm, d)           0

/* vcpu constants */
#define VPF_down    (1U << 0)
#define VPF_blocked (1U << 1)

/* XEN_DOMCTL_soft_reset_cont is inside #ifdef __XEN__ in public/domctl.h */
#ifndef XEN_DOMCTL_soft_reset_cont
#define XEN_DOMCTL_soft_reset_cont 23
#endif

/* paddr_bits: physical address bit-width variable in the real hypervisor */
#define paddr_bits PADDR_BITS

/* RCU domain locking (additional stubs beyond rcu_lock_domain already there) */
#define rcu_unlock_domain(d)       ((void)(d))
#define dom_io                     (&test_dummy_domain1)

/* vcpu_guest_context allocation helpers */
#define alloc_vcpu_guest_context()  calloc(1, sizeof(struct vcpu_guest_context))
#define free_vcpu_guest_context(p)  free(p)

/* rwlock write-side operations (xen/rwlock.h blocked; rwlock_t = spinlock_t) */
#define write_lock(rwl)   spin_lock(rwl)
#define write_unlock(rwl) spin_unlock(rwl)

/* Domain lifecycle stubs */
#define domain_pause(d)                          ((void)(d))
#define domain_unpause(d)                        ((void)(d))
#define domain_resume(d)                         ((void)(d))
#define domain_kill(d)                           0
#define domain_soft_reset(d, cont)               (-ENOSYS)
#define domain_create(id, cfg, hvm)              ((struct domain *)NULL)
#define domain_update_node_affinity(d)           ((void)(d))
#define domain_set_node_affinity(d, mask)        0
#define domain_pause_by_systemcontroller(d)      0
#define domain_unpause_by_systemcontroller(d)    0
#define domain_set_time_offset(d, off)           ((void)(d))
#define get_domain_by_id(id)                     ((struct domain *)NULL)
#define hypercall_create_continuation(...)       0

/* vCPU stubs */
#define vcpu_pause(v)      ((void)(v))
#define vcpu_unpause(v)    ((void)(v))

/* Scheduling / affinity stubs */
#define sched_adjust(d, op)               0
#define vcpu_affinity_domctl(d, cmd, aff) 0

/* IOMEM and MMIO stubs */
#define iomem_access_permitted(d, ...)      false
#define iomem_permit_access(d, ...)         0
#define iomem_deny_access(d, ...)           0
#define paging_mode_translate(d)            false
#define map_mmio_regions(d, gfn, nr, mfn)   0
#define unmap_mmio_regions(d, gfn, nr, mfn) 0
#define _gfn(x)                             ((gfn_t)(x))
#define is_hardware_domain(d)               false
#define is_xenstore_domain(d)               false

/* Misc domctl sub-operation stubs */
#define vm_event_domctl(d, op)            (-EOPNOTSUPP)
#define set_global_virq_handler(d, virq)  0
#define iommu_do_domctl(op, d, u)         (-EOPNOTSUPP)
#define get_domain_state(st, d, id)       (-EOPNOTSUPP)
#define arch_do_domctl(op, d, u)          (-EOPNOTSUPP)

/* Provide no-op stubs for these */
domid_t domid_alloc(domid_t domid)
{
    return domid;
}

/* For do_domctl() to work with multiple domains for testing claims */
struct domain *rcu_lock_domain_by_id(domid_t domain_id)
{
    struct domain *d;

    for_each_domain ( d )
    {
        if ( d->domain_id == domain_id )
            return d;
    }
    return NULL;
}

struct vcpu *vcpu_create(struct domain *d, unsigned int vcpu_id)
{
    (void)(d);
    (void)(vcpu_id);
    return NULL;
}

int vcpu_reset(struct vcpu *v)
{
    (void)(v);
    return 0;
}

int arch_set_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    (void)(v);
    (void)(c);
    return 0;
}
void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    (void)(v);
    (void)(c);
    return;
}

void arch_get_domain_info(const struct domain *d,
                          struct xen_domctl_getdomaininfo *info)
{
    (void)(d);
    (void)(info);
}

void arch_p2m_set_access_required(struct domain *d, bool access_required)
{
    (void)(d);
    (void)(access_required);
}

#endif
#endif
