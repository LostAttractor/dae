//go:build cgo && linux

// SPDX-License-Identifier: AGPL-3.0-only

package quickjs

import (
	"os"
	"runtime"
	"testing"
)

func init() {
	if os.Getenv("DAE_QEMU_TEST_WORKER") == "1" {
		// Pin during initialization, while Go guarantees the initial thread.
		runtime.LockOSThread()
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("DAE_QEMU_TEST_WORKER") != "1" {
		os.Exit(m.Run())
	}
	// Avoid musl's main-stack mremap probe under qemu-user, whose emulated
	// errors can make pthread_getattr_np scan indefinitely. A worker pthread
	// has known stack bounds. This mode is enabled only by the QEMU runner.
	result := make(chan int, 1)
	go func() { result <- m.Run() }()
	os.Exit(<-result)
}
