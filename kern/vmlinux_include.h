/* SPDX-License-Identifier: AGPL-3.0-only */

#ifndef DAE_VMLINUX_INCLUDE_H
#define DAE_VMLINUX_INCLUDE_H

/* BTF dumps can emit standalone declarations for anonymous members. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "headers/vmlinux.h"
#pragma clang diagnostic pop

#endif
