/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Minimal shim to include xen/common/page_alloc.c in host-side tests.
 *
 * This shim provides the minimal Xen definitions that page_alloc.c
 * needs to run in a host-side test environment.  It replaces a
 * minimal subset of the Xen environment that xen/common/page_alloc.c
 * interacts with with stubs so it can run in the test environment,
 * allowing test scenarios to verify the behavior of page_alloc.c.
 *
 * Copyright (C) 2026 Cloud Software Group
 */
#ifndef _TEST_ALLOC_PAGE_ALLOC_SHIM_
#define _TEST_ALLOC_PAGE_ALLOC_SHIM_

/*
 * Guard against language servers and linters picking up this header.
 *
 * This shim is intended to be used in test programs for testing the
 * code of xen/common/page_alloc.c in a host-side test environment,
 * and test programs need to define TEST_WRAP_XEN_COMMON_PAGE_ALLOC_C
 * to enable the definitions in this header.
 */
#ifndef TEST_WRAP_XEN_COMMON_PAGE_ALLOC_C
#warning "Include this header only in integration tests using page_alloc.c"
#else

/*
 * Inside the intended test context. Provide stub definitions.
 */

#define CONFIG_SCRUB_DEBUG

/* Provide struct page_info and related Xen definitions */
#include "mock-page-list.h"
#include <xen/keyhandler.h>
#include <xen/page-size.h>
#include <public/xen.h>

#define register_t foo; /* Workarounf for arm64 sys/types conflict */
#include <asm/types.h>
#undef  register_t

/* Include xen/numa.h with stubs and unused parameter warnings disabled */
#define cpumask_clear_cpu(cpu, mask) ((void)(cpu), (void)(mask))
#define mfn_to_pdx(mfn)              ((unsigned long)(mfn))
#pragma GCC diagnostic push
#ifndef CONFIG_NUMA
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <xen/numa.h>
#pragma GCC diagnostic pop

/* Flexible definition to support 32- and 64-bit architectures */
#undef PADDR_BITS
#define PADDR_BITS              (BITS_PER_LONG - PAGE_SHIFT)
#define pfn_to_paddr(pfn)       ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)        ((unsigned long)((pa) >> PAGE_SHIFT))
#define INVALID_MFN_INITIALIZER (~0UL)

typedef unsigned long nodemask_t;

/*
 * Block xen/rwlock.h's problematic cascade.  Provide a minimal rwlock_t
 * using the shim's spinlock_t (bool).
 */
typedef spinlock_t rwlock_t;

/*
 * Provide stubs for types from blocked headers that xen/sched.h's struct
 * domain and struct vcpu reference by value.  These are minimal empty
 * definitions sufficient to make the structs compile in the test context.
 */
typedef spinlock_t rspinlock_t;
typedef cpumask_t *cpumask_var_t;

/* Minimal struct defs for value-type fields in struct domain / struct vcpu */
struct list_head { struct list_head *next, *prev; };
struct timer {};
struct arch_domain {};
struct arch_vcpu {};
struct arch_vcpu_io {};
struct lock_profile {};
struct lock_profile_qhead {};
struct tasklet {};
struct domain_iommu {};
struct vpci_vcpu {};
struct _rcu_read_lock {};
typedef struct _rcu_read_lock rcu_read_lock_t;

#if defined(_ASM_X86_NOSPEC_H)
static inline bool evaluate_nospec(bool c)
{
    return c;
}
#endif

/* rcu_dereference is used by for_each_domain in sched.h (rcupdate.h blocked) */
#define rcu_dereference(p) (p)

/* perfc_incr is used in SCHED_STAT_CRANK (perfc.h blocked) */
#define perfc_incr(x)      ((void)0)

/*
 * Macros and stubs needed by sched.h's inline function bodies during header
 * compilation.  These come from headers that are blocked above.  Some are
 * also redefined in the stubs section below.
 */

/*
 * RCU annotation and helper stubs.  rcupdate.h is blocked; provide the
 * minimal definitions that radix-tree.h and sched.h need during compilation.
 */
#define __rcu                           /* RCU ownership annotation (empty) */
#define rcu_assign_pointer(p, v)        ((p) = (v))
struct rcu_head {
    struct rcu_head *next;
    void             (*func)(struct rcu_head *);
};

static struct vcpu *current;  /* zero-init; assigned via constructor below */

/* Macros used by sched.h inline functions (blocked headers provide these) */
#define cpumask_weight(mask)  1U
#define rcu_read_lock(lock)   ((void)(lock))
#define rcu_read_unlock(lock) ((void)(lock))

/*
 * Minimal per-CPU stubs: sched.h uses DECLARE_PER_CPU and this_cpu() in
 * inline functions.  These come from the blocked percpu.h.  Map onto simple
 * file-scope static variables to satisfy compilation.
 */
#define DECLARE_PER_CPU(type, name) static __used type shim_per_cpu__##name
#define this_cpu(x)                 (shim_per_cpu__##x)

/*
 * page_to_list is a macro in mock-page-list.h (included earlier) AND a
 * static inline in sched.h.  Undefine the macro before the include so that
 * sched.h can define the function without a conflicting macro expansion.
 * The mock macro is restored after sched.h is included.
 */
#undef page_to_list
#define is_xen_heap_page(pg)  false
#define is_xen_fixed_mfn(mfn) false
#define is_xen_heap_mfn(mfn)  false

/*
 * domain_crash has a 1-arg macro in hypervisor-macros.h and a variadic
 * macro in sched.h.  Undefine before the include to avoid -Wmacro-redefined;
 * sched.h's variadic version plus the __domain_crash() stub provided below
 * give us the correct behaviour in the test context.
 */
#undef domain_crash

/* ioreq.h provides ioreq_t used by struct vcpu_io inside sched.h */
#include <public/hvm/ioreq.h>

/* DECLARE_BITMAP from xen/types.h (blocked by __TYPES_H__); BITS_TO_LONGS provided
 * by xen-tools/bitops.h already included via hypervisor-macros.h. */
#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]

/*
 * Include the real xen/sched.h to get struct domain, struct vcpu, and
 * all related declarations.  The guards above prevent conflicting
 * subsidiary headers from being pulled in.  Suppress warnings about
 * unused parameters in the Xen header inline functions.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <xen/sched.h>
/* Hypercall preemption: never preempt hypercalls in the test environment. */
#undef hypercall_preempt_check
#define hypercall_preempt_check()       0
#pragma GCC diagnostic pop

/*
 * Restore mock page_to_list behaviour: all pages go into a single test
 * page-list regardless of their type flags.  The static inline defined in
 * sched.h is immediately shadowed by this macro so that page_alloc.c sees
 * the test list that the test helpers can inspect and reset.
 */
#undef page_to_list
#define page_to_list(d, pg) (&test_page_list)

/*
 * Restore test-friendly overrides for sched.h macros that reference
 * real Xen runtime infrastructure (domain_destroy, etc.).
 */
#undef put_domain
#define put_domain(d)       ((void)(d))

/*
 * Provide two domains for the test context, so that test helpers can call
 * allocator functions that require domain context and verify behavior that
 * depends on domain state, such as claims accounting and page allocation
 * for specific domains.
 */
static struct domain test_dummy_domain1;
static struct domain test_dummy_domain2;
static struct domain __used *dom1 = &test_dummy_domain1;
static struct domain __used *dom2 = &test_dummy_domain2;

/* RCU domain locking (additional stubs beyond rcu_lock_domain already there) */
#define rcu_unlock_domain(d) ((void)(d))
#define dom_io               (&test_dummy_domain1)
#define dom_xen              (&test_dummy_domain2)

/* To provide a current vcpu/domain pair for code paths that inspect it. */
static unsigned char test_dummy_storage[PAGE_SIZE];
static struct vcpu test_current_vcpu;
/* 'current' was forward-declared before sched.h.  Set the pointer at
 * program startup via a constructor so that test helpers see the right vcpu
 * from the very first call into the allocator. */
static void __attribute__((constructor)) _page_alloc_shim_init_current(void)
{
    current = &test_current_vcpu;
}
static cpumask_t cpu_online_map = ~0UL;

#define for_each_online_node(i) for ( (i) = 0; (i) < MAX_NUMNODES; ++(i) )
#define for_each_cpu(i, mask)   for ( (i) = 0; (i) < 1; ++(i) )

/* dom_cow is a domain pointer used by the memory sharing code */
#ifdef CONFIG_MEM_SHARING
static struct domain *dom_cow;
#else
#define dom_cow NULL
#endif

/*
 * Logging spinlock for the test context
 */
static spinlock_t *heap_lock_ptr;

/* Helper function to track spinlock actions for additional context */
static void print_spinlock(const char *action, spinlock_t *lock,
                           const char *file, int line, const char *func)
{
    const char *relpath = file;

    if ( !testcase_assert_verbose_assertions )
        return;

    while ( (file = strstr(relpath, "../")) )
        relpath += 3;

    for ( int i = 0; i < testcase_assert_verbose_indent_level; i++ )
        printf("  ");

    /* Print the path first:*/
    if ( testcase_assert_current_func == NULL ||
         strcmp(testcase_assert_current_func, func) != 0 )
        printf("%s:%d: %s(): ", relpath, line, func);
    else
        printf("%s:%d: ", relpath, line);

    if ( lock == heap_lock_ptr )
        printf("heap_lock %s\n", action);
    else if ( domain_list && lock == &test_dummy_domain1.page_alloc_lock )
        printf("dom1->page_alloc_lock %s\n", action);
    else if ( domain_list && lock == &test_dummy_domain2.page_alloc_lock )
        printf("dom2->page_alloc_lock %s\n", action);
    else
        printf("unknown lock %p %s\n", (void *)lock, action);
}

/*
 * For the test context, we assume all locks are always held to avoid having
 * to manage lock state in the test helpers.  This allows the test helpers
 * to call allocator functions that require locks to be held without needing
 * to acquire those locks, which simplifies the test code and focuses on
 * exercising the allocator logic under test.
 *
 * Invariants that would normally be protected by locks must still be upheld
 * by the test helpers, but the test helpers can assume they have exclusive
 * access to the allocator state and do not need to worry about concurrency.
 */
#define spin_is_locked(l)         true
#define rspin_is_locked(l)        true

/* memflags: */
#define _MEMF_no_refcount         0
#define MEMF_no_refcount          (1U << _MEMF_no_refcount)
#define _MEMF_populate_on_demand  1
#define MEMF_populate_on_demand   (1U << _MEMF_populate_on_demand)
#define _MEMF_keep_scrub          2
#define MEMF_keep_scrub           (1U << _MEMF_keep_scrub)
#define _MEMF_no_dma              3
#define MEMF_no_dma               (1U << _MEMF_no_dma)
#define _MEMF_exact_node          4
#define MEMF_exact_node           (1U << _MEMF_exact_node)
#define _MEMF_no_owner            5
#define MEMF_no_owner             (1U << _MEMF_no_owner)
#define _MEMF_no_tlbflush         6
#define MEMF_no_tlbflush          (1U << _MEMF_no_tlbflush)
#define _MEMF_no_icache_flush     7
#define MEMF_no_icache_flush      (1U << _MEMF_no_icache_flush)
#define _MEMF_no_scrub            8
#define MEMF_no_scrub             (1U << _MEMF_no_scrub)
#define _MEMF_node                16
#define MEMF_node_mask            ((1U << (8 * sizeof(nodeid_t))) - 1)
#define MEMF_node(n)              ((((n) + 1)&MEMF_node_mask) << _MEMF_node)
#define MEMF_get_node(f)          ((((f) >> _MEMF_node) - 1)&MEMF_node_mask)
#define _MEMF_bits                24
#define MEMF_bits(n)              ((n) << _MEMF_bits)

#define string_param(name, var)
#define custom_param(name, fn)
#define size_param(name, var)
#define boolean_param(name, func)
#define integer_param(name, var)

#define page_to_virt(pg)     ((void *)(pg))
#define virt_to_page(v)      ((struct page_info *)(v))
#define mfn_to_virt(mfn)     ((void *)&test_dummy_storage)
#define __mfn_to_virt(mfn)   mfn_to_virt(mfn)
#define _mfn(x)              ((mfn_t)(x))
#define mfn_x(x)             ((unsigned long)(x))
#define mfn_add(mfn, nr)     ((mfn) + (nr))
#define mfn_min(a, b)        ((a) < (b) ? (a) : (b))

/* NUMA stubs for unit testing NUMA-aware page allocator logic. */
#define first_node(mask)                    \
        ({                                  \
             unsigned long __mask = (mask); \
             __builtin_ffs(__mask) - 1;     \
         })
#define next_node(node, mask)                                              \
        ({                                                                 \
             unsigned long __mask = (mask) & ~((1UL << ((node) + 1)) - 1); \
             __builtin_ffs(__mask) - 1;                                    \
         })
#define cycle_node(node, mask)                                             \
        ({                                                                 \
             unsigned long __mask = (mask) & ~((1UL << ((node) + 1)) - 1); \
             int __next = __builtin_ffs(__mask) - 1;                       \
             __next >= 0 ? __next : first_node(mask);                      \
         })
#define num_online_nodes()        MAX_NUMNODES
#define node_online(node)         ((node) < MAX_NUMNODES)
static nodemask_t node_online_map = ~0UL;

#ifdef CONFIG_NUMA
#define __node_distance(a, b) 0
nodeid_t cpu_to_node[NR_CPUS];
cpumask_t node_to_cpumask[MAX_NUMNODES];
struct node_data node_data[MAX_NUMNODES];
unsigned int memnode_shift;

static typeof(*memnodemap) _memnodemap[64];
nodeid_t *memnodemap = _memnodemap;
unsigned long memnodemapsize = sizeof(_memnodemap);
#endif /* CONFIG_NUMA */

/*
 * Stub definitions for Xen functions and macros used by page_alloc.c,
 * sufficient to support the test scenarios in tools/tests/alloc.
 *
 * These are not intended to be complete or accurate for general use
 * in other test contexts or as a general-purpose shim for page_alloc.c.
 */
#define rcu_lock_domain(id)               (&test_dummy_domain1)
#define rcu_lock_domain_by_any_id(id)     (&test_dummy_domain1)
#define NOW()                             0LL
#define SYS_STATE_active                  1
#define system_state                      0
#define cpu_online(cpu)                   ((cpu) == 0)
#define smp_processor_id()                0U
/* smp_wmb and cpumask_weight defined before sched.h include; identical
 * redefinitions here are benign but kept for clarity. */
#define cpumask_empty(mask)               true
#define cpumask_clear(mask)               ((void)(mask))
#define cpumask_and(dst, a, b)            ((void)(dst), (void)(a), (void)(b))
#define cpumask_or(dst, a, b)             ((void)(dst), (void)(a), (void)(b))
#define cpumask_copy(dst, src)            ((void)(dst), (void)(src))
#define cpumask_first(mask)               0U
#define cpumask_intersects(a, b)          false
/* cpumask_weight defined before sched.h; identical redefinition is benign */
#define __cpumask_set_cpu(cpu, mask)      ((void)(cpu), (void)(mask))
#define page_get_owner(pg)                ((pg)->owner)
#define page_set_owner(pg, d)             ((pg)->owner = (d))
#define page_get_owner_and_reference(pg)  ((pg)->owner)
#define set_gpfn_from_mfn(mfn, gpfn)      ((void)0)
#define page_is_offlinable(mfn)           true
#define softirq_pending(cpu)              false
#define process_pending_softirqs()        ((void)0)
#define on_selected_cpus(msk, f, data, w) ((void)0)
#define get_order_from_pages(nr)          0U
#define get_order_from_bytes(bytes)       0U
#define arch_mfns_in_directmap(mfn, nr)   true
#define maddr_to_mfn(pa)                  ((mfn_t)paddr_to_pfn(pa))
#define unmap_domain_page(ptr)            ((void)(ptr))

#define ASSERT_ALLOC_CONTEXT()              ((void)0)
#define arch_free_heap_page(d, pg)          ((void)(d), (void)(pg))
#define get_knownalive_domain(d)            ((void)(d))
#define domain_clamp_alloc_bitsize(d, bits) (bits)
#define mem_paging_enabled(d)               false

#if defined(__x86_64__)
#define clear_page_hot(ptr)  memset((ptr), 0, PAGE_SIZE)
#define clear_page_cold(ptr) memset((ptr), 0, PAGE_SIZE)
#define scrub_page_hot(ptr)  clear_page_hot(ptr)
#define scrub_page_cold(ptr) clear_page_cold(ptr)
#endif

#define put_page(pg)      ((void)(pg))
bool get_page(struct page_info *page, const struct domain *domain)
{
    (void)page;
    (void)domain;
    return false;
}

typedef unsigned long gfn_t;
static inline gfn_t __must_check gfn_add(gfn_t gfn, unsigned long i)
{
    return (gfn) + i;
}

unsigned int arch_get_dma_bitsize(void)
{
    return 32U;
}

/* LLC (Last Level Cache) coloring support stubs */
#define llc_coloring_enabled false
unsigned int get_max_nr_llc_colors(void)
{
    return 1U;
}
unsigned int page_to_llc_color(const struct page_info *pg)
{
    (void)pg;
    return 0U;
}

#define parse_bool(s, e) (-1) /* Not parsed, use the default */

void __init register_keyhandler(unsigned char key, keyhandler_fn_t *fn,
                                const char *desc, bool diagnostic)
{
    (void)key;
    (void)fn;
    (void)desc;
    (void)diagnostic;
}

void send_global_virq(uint32_t virq)
{
    (void)virq;
}

unsigned long simple_strtoul(const char *cp, const char **endp,
                             unsigned int base)
{
    return strtoul(cp, (char **)endp, base);
}

/*
 * __domain_crash is declared by sched.h (via domain_crash macro) but has no
 * definition for the test environment.  Provide a no-op stub so the test
 * binary links correctly if domain_crash is ever expanded.
 */
void __domain_crash(struct domain *d)
{
    (void)d;
}
#endif
#endif
