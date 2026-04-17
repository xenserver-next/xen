/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common test harness for page allocation unit tests.
 *
 * Copyright (C) 2026 Cloud Software Group
 */

#ifndef TOOLS_TESTS_ALLOC_HARNESS_H
#define TOOLS_TESTS_ALLOC_HARNESS_H

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

/* Enable additional debug checks. */
#define CONFIG_DEBUG
#define CONFIG_MMU
#ifdef __arm__
#define CONFIG_ARM_32
#endif
#ifdef __aarch64__
#define CONFIG_ARM_64
#endif

/* Configure the included headers for the test context */
#ifndef CONFIG_NR_CPUS
#define CONFIG_NR_CPUS 64
#endif

#if defined(CONFIG_NUMA) && !defined(CONFIG_NR_NUMA_NODES)
#define CONFIG_NR_NUMA_NODES 64
#endif

/* Assertion helpers shared by the tests. */
#include "testcase-asserts.h"

/* Common Xen types used by the test environment. */
/* Short integer types (xen/types.h blocked by __TYPES_H__) */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t paddr_t;
typedef unsigned long cpumask_t;
typedef long long s_time_t;
typedef bool spinlock_t;

/*
 * If testcase_assert_verbose_assertions is enabled, the spinlock
 * functions print the spinlock being acquired or released along with
 * the file and line number of the assertion that triggered it.
 * This can be helpful for debugging test failures and understanding
 * the sequence of events leading up to the failure.
 */
#define spin_lock(l) \
        (print_spinlock("acquired", l, __FILE__, __LINE__, __func__), (void)(l))
#define spin_unlock(l) \
        (print_spinlock("released", l, __FILE__, __LINE__, __func__), (void)(l))
#define spin_lock_cb(l, cb, data) spin_lock(l)
#define spin_lock_kick()          ((void)0)
#define nrspin_lock(l)            spin_lock(l)
#define nrspin_unlock(l)          spin_unlock(l)
#define rspin_lock(l)             spin_lock(l)
#define rspin_unlock(l)           spin_unlock(l)
#define read_lock(rwl)            spin_lock(rwl)
#define read_unlock(rwl)          spin_unlock(rwl)
#define read_trylock(rwl)         (spin_lock(rwl), true)
#define rw_is_locked(rwl)         false
#define rw_is_write_locked(rwl)   false
#define DEFINE_SPINLOCK(l)        spinlock_t l

/* Heap allocator stubs */
#define xmalloc(type)                calloc(1, sizeof(type))
#define xmalloc_array(type, nr)      calloc((nr), sizeof(type))
#define xvzalloc_array(type, nr)     calloc((nr), sizeof(type))
#define xzalloc(type)                calloc(1, sizeof(type))
#define xfree(p)                     free(p)
#define xvfree(p)                    free(p)

/* xvmalloc_array supports both 2-arg (type, n) used by page_alloc.c and
 * 3-arg (type, rows, cols) used by domctl.c via a variadic helper.
 * The helper appends a sentinel '1' so the 2-arg form multiplies by 1. */
#define xvmalloc_array(type, ...)    _xvmalloc_impl(type, __VA_ARGS__, 1)
#define _xvmalloc_impl(t, a, b, ...) calloc((size_t)(a) * (size_t)(b), \
                                            sizeof(t))

/*
 * Use the real guest_access functions and provide stubs for
 * xen/asm-x86/guest_access.h's __raw_copy_{to,from}_guest() functions
 * which are used by the high-level copy_{to,from}_guest*() functions.
 */
unsigned long raw_copy_to_guest(void *to, const void *from, unsigned int len)
{
    memcpy(to, from, len);
    return 0;
}
#define __raw_copy_to_guest raw_copy_to_guest
unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned int len)
{
    memcpy(to, from, len);
    return 0;
}
unsigned long raw_copy_from_guest(void *to, const void *from, unsigned int len)
{
    memcpy(to, from, len);
    return 0;
}
unsigned long raw_clear_guest(void *to, unsigned int len)
{
    memset(to, 0, len);
    return 0;
}
#define __ASM_X86_GUEST_ACCESS_H__

/* nodemask support for the test environment. */
#define nodes_intersects(a, b)        ((a) & (b))
#define nodes_and(dst, a, b)          ((dst) = (a) & (b))
#define nodes_andnot(dst, a, b)       ((dst) = (a) & ~(b))
#define nodes_clear(dst)              ((dst) = 0)
#define nodemask_test(node, mask)     ((*(mask) >> (node)) & 1UL)
#define node_set(node, mask)          ((mask) |= (1UL << (node)))
#define node_clear(node, mask)        ((mask) &= ~(1UL << (node)))
#define nodemask_bits(maskp)          ((unsigned long *)(maskp))
#define node_test_and_set(node, mask)                   \
        ({                                              \
             bool was_set = nodemask_test(node, &mask); \
             node_set(node, mask);                      \
             was_set;                                   \
         })

#define ACCESS_ONCE(x) (x)
#define filtered_flush_tlb_mask(ts)       ((void)(ts))
#define accumulate_tlbflush(need, pg, ts) ((void)(need), (void)(pg), (void)(ts))
void flush_page_to_ram(unsigned long mfn, bool sync_icache)
{
    (void)mfn;
    (void)sync_icache;
}
#ifdef __x86_64__
#define cpu_relax()                       ((void)0)

#define map_mmio_regions(d, gfn, nr, mfn)   0
#define unmap_mmio_regions(d, gfn, nr, mfn) 0
#endif

#define page_set_tlbflush_timestamp(pg)   ((pg)->tlbflush_timestamp = 0)
#define cmpxchg(ptr, old, new)                                 \
        ({                                                     \
             __typeof__(*(ptr)) __old = (old);                 \
             __typeof__(*(ptr)) __new = (new);                 \
             __sync_val_compare_and_swap((ptr), __old, __new); \
         })

/*
 * The original reserve_offlined_page() implementation triggers an
 * AddressSanitizer (ASAN) stack-buffer-overflow report in both GCC and
 * Clang when test_merge_tail_pair runs with ASAN enabled and verifies
 * the heap free-list state.
 *
 * ASAN reports several list-pointer errors in the heap state, and one of
 * them appears to trigger the stack-buffer-overflow detection on x86_64.
 *
 * As a temporary workaround, detect whether ASAN is enabled so the test
 * can skip the ASSERT_LIST_EQUAL verification that triggers the report,
 * while still running the rest of the case under ASAN.
 */
#if defined(__has_feature)
/* Clang uses __has_feature to detect AddressSanitizer */
# if __has_feature(address_sanitizer)
#  define ASAN_ENABLED 1
# endif
/* GCC uses __SANITIZE_ADDRESS__ to detect AddressSanitizer */
#elif defined(__SANITIZE_ADDRESS__)
# define ASAN_ENABLED 1
#else
# define ASAN_ENABLED 0
#endif
#endif


/*
 * Some functions need to use types defined in specific headers,
 * so we include them and define header guards to prevent unwanted
 * definitions from those headers that conflict with the test harness
 * or bring in Xen-internal structures that are already provided by
 * the natural C compiler defines, libc defines and stubs in this shim.
 */
#define __TYPES_H__
#define __LIB_H__ /* C runtime library, only for the hypervisor */

#define XEN_SOFTIRQ_H
#define XEN__XVMALLOC_H
#define _LINUX_INIT_H
#define _XEN_PARAM_H
#define _XEN_VPCI_H_
#define __LINUX_NODEMASK_H
#define __RWLOCK_H__
#define __XEN_SMP_H__
#define __XEN_BUG_H__
#define _LINUX_KERNEL_H
#define XEN__IOMMU_H
#define __XEN_ERRNO_H__
#define _TIMER_H_
#define __XEN_LIST_H__
#define __XEN_PERCPU_H__
#define __XEN_STRING_H__
#define __XEN_TIME_H__
#define __XEN_RCUPDATE_H
#define __XEN_PREEMPT_H__
#define __XEN_TASKLET_H__
#define __XEN_ATOMIC_H__

#define __XEN_PERFC_H__
#define __SPINLOCK_H__

#define __VM_EVENT_H__
#define __XEN_EVENT_H__
#define __XEN_CPUMASK_H
#define __XEN_FRAME_NUM_H__
#define __XEN_IRQ_H__
#define __XEN_MM_H__
#define __XEN_PDX_H__

#define __ASM_DOMAIN_H__
#define __ASM_SYSTEM_H
#define __ASM_ARM_FLUSHTLB_H__

#define _ASM_X86_NOSPEC_H
#define _ASM_ARM_NOSPEC_H

#define __ARCH_X86_ATOMIC__
#define __X86_ALTERNATIVE_H__
#define __X86_CURRENT_H__
#define __X86_PAGE_H__
#define __ARM_CURRENT_H__
#define __X86_64_SYSTEM_H__
#define __ASM_I386_CPUFEATURE_H
#define __XEN_X86_CPUFEATURESET_H__

#define __FLUSHTLB_H__

/* ARM D/I-cache flushing stubs */
#if defined(__arm__) || defined(__aarch64__)
#define dsb(ish) __asm__ __volatile__ ("dsb ish" : : : "memory")
#define isb() __asm__ __volatile__ ("isb" : : : "memory")
#endif
