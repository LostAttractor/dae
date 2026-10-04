/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestLinkSnapshotDisappeared(t *testing.T) {
	stale := &netlink.Dummy{Index: 2, Name: "eth0"}
	for _, tc := range []struct {
		name      string
		cause     error
		current   netlink.Link
		lookupErr error
		want      bool
	}{
		{name: "removed", cause: fmt.Errorf("read sysctl: %w", unix.ENOENT), lookupErr: unix.ENODEV, want: true},
		{name: "replaced", cause: fmt.Errorf("read sysctl: %w", unix.ENOENT), current: &netlink.Dummy{Index: 3, Name: "eth0"}, want: true},
		{name: "sysctl missing on live link", cause: fmt.Errorf("read sysctl: %w", unix.ENOENT), current: stale},
		{name: "permission denied", cause: fmt.Errorf("read sysctl: %w", unix.EACCES), lookupErr: unix.ENODEV},
		{name: "dual disappearance", cause: errors.Join(unix.ENOENT, unix.ENODEV), lookupErr: unix.ENODEV, want: true},
		{name: "rollback failure", cause: errors.Join(unix.ENOENT, unix.EIO), lookupErr: unix.ENODEV},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := linkSnapshotDisappeared(stale, tc.cause, func(name string) (netlink.Link, error) {
				if name != "eth0" {
					t.Fatalf("lookup name = %q, want eth0", name)
				}
				return tc.current, tc.lookupErr
			})
			if got != tc.want {
				t.Fatalf("linkSnapshotDisappeared() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestControlPlaneCoreCleanupOwnership(t *testing.T) {
	core := &controlPlaneCore{kernelLinks: new(kernelLinks)}
	var cleaned []string
	record := func(name string) func() error {
		return func() error {
			cleaned = append(cleaned, name)
			return nil
		}
	}

	core.addCleanup(record("static-first"))
	core.addCleanup(record("static-last"))
	owned := hostTCXLink{linkIndex: 1, role: hostTCXLanIngress, close: record("owned-link")}
	if !core.ownHostTCXLink(owned) {
		t.Fatal("first ownership registration was rejected")
	}
	if core.ownHostTCXLink(hostTCXLink{linkIndex: 1, role: hostTCXLanIngress, close: record("duplicate-link")}) {
		t.Fatal("duplicate ownership registration was accepted")
	}
	released := hostTCXLink{linkIndex: 2, role: hostTCXWanIngress, close: record("released-link")}
	core.ownHostTCXLink(released)
	if err := core.closeHostTCXLinks(released.linkIndex); err != nil {
		t.Fatal(err)
	}
	released.close = record("recreated-link")
	core.ownHostTCXLink(released)

	for _, cleanup := range core.takeCleanups() {
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"released-link", "static-last", "static-first"}
	if !slices.Equal(cleaned, want) {
		t.Fatalf("cleanup order = %v, want %v", cleaned, want)
	}
	if cleanups := core.takeCleanups(); len(cleanups) != 0 {
		t.Fatalf("cleanup ownership was not drained: %d entries", len(cleanups))
	}
	if err := core.kernelLinks.Close(); err != nil {
		t.Fatal(err)
	}
	want = append(want, "recreated-link", "owned-link")
	if !slices.Equal(cleaned, want) {
		t.Fatalf("shared datapath cleanup = %v, want %v", cleaned, want)
	}
}

func TestControlPlaneCoreCleanupRegistrationConcurrent(t *testing.T) {
	core := &controlPlaneCore{kernelLinks: new(kernelLinks)}
	var workers sync.WaitGroup
	for i := range 100 {
		workers.Go(func() {
			core.addCleanup(func() error { return nil })
			core.ownHostTCXLink(hostTCXLink{linkIndex: i, close: func() error { return nil }})
		})
	}
	workers.Wait()
	if cleanups := core.takeCleanups(); len(cleanups) != 100 || len(core.hostTCXLinks) != 100 {
		t.Fatalf("cleanup count = %d, shared attachments = %d; want 100 each", len(cleanups), len(core.hostTCXLinks))
	}
}
