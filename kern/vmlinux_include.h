/* SPDX-License-Identifier: AGPL-3.0-only */

#ifndef DAE_VMLINUX_INCLUDE_H
#define DAE_VMLINUX_INCLUDE_H

#if defined(__clang__) && __clang_major__ < 15
#pragma clang diagnostic push
#pragma clang diagnostic warning "-W#warnings"
#warning "dae eBPF is tested with Clang 15 or newer; this compiler is outside the tested range"
#pragma clang diagnostic pop
#endif

/* BTF dumps can emit standalone declarations for anonymous members. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "headers/vmlinux.h"
#pragma clang diagnostic pop

#endif
