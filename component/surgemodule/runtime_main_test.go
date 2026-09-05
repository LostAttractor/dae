//go:build cgo

// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"os"
	"runtime"
	"testing"
)

func init() {
	if os.Getenv("DAE_QEMU_TEST_WORKER") == "1" {
		// Package initialization runs on the initial thread. Pin it before
		// main can migrate, then keep it parked throughout the test run.
		runtime.LockOSThread()
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("DAE_QEMU_TEST_WORKER") != "1" {
		os.Exit(m.Run())
	}
	// Some qemu-user targets return ENOMEM for every page in musl's
	// pthread_getattr_np main-stack probe. Keep the initial thread parked so
	// tests use Go-created pthreads, whose stack bounds musl already knows.
	// Native tests keep their normal entry point and exercise both thread kinds.
	result := make(chan int, 1)
	go func() { result <- m.Run() }()
	os.Exit(<-result)
}
