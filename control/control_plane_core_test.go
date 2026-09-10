/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"slices"
	"sync"
	"testing"
)

func TestControlPlaneCoreCleanupOwnership(t *testing.T) {
	core := &controlPlaneCore{}
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
	want := []string{"released-link", "recreated-link", "owned-link", "static-last", "static-first"}
	if !slices.Equal(cleaned, want) {
		t.Fatalf("cleanup order = %v, want %v", cleaned, want)
	}
	if cleanups := core.takeCleanups(); len(cleanups) != 0 {
		t.Fatalf("cleanup ownership was not drained: %d entries", len(cleanups))
	}
}

func TestControlPlaneCoreCleanupRegistrationConcurrent(t *testing.T) {
	core := &controlPlaneCore{}
	var workers sync.WaitGroup
	for i := 0; i < 100; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			core.addCleanup(func() error { return nil })
			core.ownHostTCXLink(hostTCXLink{linkIndex: i, close: func() error { return nil }})
		}(i)
	}
	workers.Wait()
	if cleanups := core.takeCleanups(); len(cleanups) != 200 {
		t.Fatalf("cleanup count = %d, want 200", len(cleanups))
	}
}
