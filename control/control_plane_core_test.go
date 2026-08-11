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
	core := &controlPlaneCore{filterCleanups: make(map[filterCleanupKey]func() error)}
	var mu sync.Mutex
	var cleaned []string
	record := func(name string) func() error {
		return func() error {
			mu.Lock()
			cleaned = append(cleaned, name)
			mu.Unlock()
			return nil
		}
	}

	core.addCleanup(record("static-first"))
	core.addCleanup(record("static-last"))
	key := filterCleanupKey{namespace: "host", linkIndex: 1, parent: 2, handle: 3}
	core.ownFilter(key, record("stale-filter"))
	core.ownFilter(key, record("replacement-filter"))
	released := filterCleanupKey{namespace: "host", linkIndex: 2, parent: 2, handle: 3}
	core.ownFilter(released, record("released-filter"))
	core.releaseLinkFilters("host", released.linkIndex)
	core.ownFilter(released, record("recreated-filter"))

	for _, cleanup := range core.takeCleanups() {
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"recreated-filter", "replacement-filter", "static-last", "static-first"}
	if !slices.Equal(cleaned, want) {
		t.Fatalf("cleanup order = %v, want %v", cleaned, want)
	}
	if cleanups := core.takeCleanups(); len(cleanups) != 0 {
		t.Fatalf("cleanup ownership was not drained: %d entries", len(cleanups))
	}
}

func TestControlPlaneCoreCleanupRegistrationConcurrent(t *testing.T) {
	core := &controlPlaneCore{filterCleanups: make(map[filterCleanupKey]func() error)}
	var workers sync.WaitGroup
	for i := 0; i < 100; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			core.addCleanup(func() error { return nil })
			core.ownFilter(filterCleanupKey{namespace: "host", linkIndex: i % 10}, func() error { return nil })
		}(i)
	}
	workers.Wait()
	if cleanups := core.takeCleanups(); len(cleanups) != 110 {
		t.Fatalf("cleanup count = %d, want 110", len(cleanups))
	}
}
