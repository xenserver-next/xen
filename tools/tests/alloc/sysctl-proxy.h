/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Wrapper around xen/common/sysctl.c for the allocator test framework.
 *
 * The test framework includes the real sysctl.c directly in its translation
 * unit, together with mocks for the Xen types and functions it uses.
 *
 * This file provides the definitions needed for that setup. It also provides
 * proxy functions to call the do_memory() functions for test scenarios
 * to install memory claims using the do_memory(), which is the real consumer
 * of the XEN_DOMCTL_claim_memory command.
 *
 * Copyright (C) 2026 Cloud Software Group
 */
#ifndef TOOLS_TESTS_ALLOC_SYSCTL_PROXY_H
#define TOOLS_TESTS_ALLOC_SYSCTL_PROXY_H

#ifdef TEST_WRAP_XEN_COMMON_SYSCTL_C
#include "sysctl-shim.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../../xen/common/sysctl.c"
#pragma GCC diagnostic pop
#endif /* TEST_WRAP_XEN_COMMON_SYSCTL_C */

#endif
