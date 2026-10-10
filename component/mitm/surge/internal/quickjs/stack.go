//go:build cgo && linux && !surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package quickjs

/*
#cgo CFLAGS: -D_GNU_SOURCE
#cgo LDFLAGS: -lpthread
#include <errno.h>
#include <pthread.h>
#include <stdint.h>

// QuickJS uses the native pthread stack. musl worker stacks can be smaller
// than the configured JS limit; retain room for Go callbacks and unwinding.
static int dae_stack_limit(size_t requested, size_t *limit) {
    const size_t reserve = 32 * 1024;
    const size_t minimum = 16 * 1024;
    // ASan may place locals on a fake stack, but this is the real frame.
    uintptr_t marker = (uintptr_t)__builtin_frame_address(0);
    pthread_attr_t attr;
    void *base;
    size_t size;
    int rc = pthread_getattr_np(pthread_self(), &attr);
    if (rc != 0) return rc;
    rc = pthread_attr_getstack(&attr, &base, &size);
    pthread_attr_destroy(&attr);
    if (rc != 0) return rc;
    uintptr_t bottom = (uintptr_t)base;
    if (marker <= bottom || marker - bottom > size) return ERANGE;
    size_t available = marker - bottom;
    if (available <= reserve || available - reserve < minimum) return ENOMEM;
    *limit = requested < available - reserve ? requested : available - reserve;
    return *limit < minimum ? ENOMEM : 0;
}
*/
import "C"

import (
	"fmt"
	"syscall"
)

func nativeStackLimit(requested uint64) (uint64, error) {
	var limit C.size_t
	if rc := C.dae_stack_limit(C.size_t(requested), &limit); rc != 0 {
		return 0, fmt.Errorf("quickjs: cannot determine safe native stack: %w", syscall.Errno(rc))
	}
	return uint64(limit), nil
}
