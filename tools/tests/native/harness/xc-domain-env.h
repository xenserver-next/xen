/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Wrapper around tools/libs/ctrl/xc_domain.c for the allocator test harness.
 *
 * The test framework includes the real xc_domain.c directly in its
 * translation unit, together with a small shim for the libxc internals it
 * uses and a proxy that redirects do_domctl(xch, domctl) to the wrapped Xen
 * domctl handler already present in this harness.
 *
 * Copyright (C) 2026 Cloud Software Group
 */
#ifndef TOOLS_TESTS_NATIVE_HARNESS_XC_DOMAIN_ENV_H
#define TOOLS_TESTS_NATIVE_HARNESS_XC_DOMAIN_ENV_H
#ifdef TEST_ENABLE_XC_DOMAIN_C

#define TEST_WRAP_XEN_COMMON_DOMCTL_C
#include "domctl-wrapper.h"

#define TEST_WRAP_TOOLS_INCLUDE_XENCTRL_H
#include "xenctrl-shim.h"

/* Hypercall passthrough of xc's do_domctl() to the hypervisor's do_domctl() */
static inline int do_domctl_hypervisor_passthrough(xc_interface *xch,
                                                   struct xen_domctl *domctl)
{
    /* Convert from domctl pointer to xen_domctl_t handle */
    union {
        XEN_GUEST_HANDLE_PARAM(xen_domctl_t) handle;
        struct xen_domctl *ptr;
    } u = { .ptr = domctl };

    domctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    ASSERT(xch == &test_xc_handle);
    return do_domctl(u.handle); /* Call xen/common/domctl.c's do_domctl() */
}

/* Make do_domctl() calls in libs/ctrl/xc_domain.c use the passthrough */
#define do_domctl do_domctl_hypervisor_passthrough

/* Include the real tools/libs/ctrl/xc_domain.c */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <../libs/ctrl/xc_domain.c>
#pragma GCC diagnostic pop

#endif
#endif
