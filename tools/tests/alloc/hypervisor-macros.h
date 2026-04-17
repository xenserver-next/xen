/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common macros and definitions for building host-side unit tests
 * for the Xen hypervisor.
 *
 * Copyright (C) 2026 Cloud Software Group
 */

#ifndef TOOLS_TESTS_ALLOC_HYPERVISOR_MACROS_H
#define TOOLS_TESTS_ALLOC_HYPERVISOR_MACROS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/*
 * In Xen, STATIC_IF(x) and config_enabled(x) are defined in kconfig.h,
 * which cannot be included here. Define the required subset locally.
 */
#define STATIC_IF(option)        static_if(option)
#define static_if(value)         _static_if(__ARG_PLACEHOLDER_##value)
#define _static_if(arg1_or_junk) ___config_enabled(arg1_or_junk static, )
#define __ARG_PLACEHOLDER_1      0,
#define IS_ENABLED(opt)          config_enabled(opt)
#define config_enabled(cfg)      _config_enabled(cfg)
#define _config_enabled(value)   __config_enabled(__ARG_PLACEHOLDER_##value)

#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)

#define ___config_enabled(__ignored, val, ...) val

/*
 * Reuse the Xen-tools macros from common-macros.h. They are not
 * necessarily identical to the hypervisor variants, but they are close
 * enough for this test environment.
 */
#include <xen-tools/common-macros.h>
/* Undefine conflicting macros from the Xen-tools headers. */
#undef BUILD_BUG_ON
#undef container_of
#undef MASK_INSR
#undef MASK_EXTR
#undef ROUNDUP
#undef ARRAY_SIZE
#undef min
#undef max
#undef min_t
#undef max_t
#undef __nonnull
#undef offsetof
#define __XEN_CONST_H__
#include <xen/compiler.h>
#include <xen/macros.h>

/*
 * Reuse the Xen-tools bit operations from bitops.h.
 * They are not identical to the hypervisor versions,
 * but they are close enough for this test environment.
 */
#include <xen-tools/bitops.h>

/*
 * After including Xen-tools bitops.h, redefine ffsl to match Xen
 * hypervisor versions to return unsigned int, which matters for
 * signed/unsigned comparisions and conversion checks and type
 * expectations, and undefine conflicting xen-tools macros.
 */
#undef BITS_PER_LONG
#undef __LITTLE_ENDIAN
#undef __BIG_ENDIAN
#undef ffsl
#define ffsl(x) ((unsigned int)__builtin_ffsl(x))
#define flsl(x) ((unsigned int)((x) ? BITS_PER_LONG - __builtin_clzl(x) : 0))
#define BUG()                     assert(false)
#define domain_crash(d)           ((void)(d))
#define PRI_mfn                   "lu"
#define PRI_stime                 "lld"
#define printk                    printf
#define dprintk(level, fmt, ...)  printk(fmt, ##__VA_ARGS__)
#define gdprintk(level, fmt, ...) printk(fmt, ##__VA_ARGS__)
#define gprintk(level, fmt, ...)  printk(fmt, ##__VA_ARGS__)
#define panic(fmt, ...)                          \
        do                                       \
        {                                        \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
            abort();                             \
        } while ( 0 )
#define __initdata
#define __init        __used
#define __initcall(f) static int __used (*f##_ptr)(void) = (f)
#endif
