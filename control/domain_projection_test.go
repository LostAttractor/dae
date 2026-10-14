// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestDomainProjectionRetriesInstalledState(t *testing.T) {
	g, fake := newTestRegistry(1, time.Minute)
	now := time.Now()
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	g.Upsert("a.example.", a, testBitmap(0), 60, now)
	failure := errors.New("map allocation unavailable")
	g.kernel.update = func(netip.Addr, []uint32, []uint32) error { return failure }
	g.Upsert("shared.example.", a, testBitmap(1), 60, now)
	bump, routing := g.kernelRoutingBitmaps(a)
	if !slices.Equal(bump, testBitmap(0)) || !slices.Equal(routing, testBitmap(0)) || g.Verify("shared.example.", a).KernelCovered {
		t.Fatal("failed update was reported as installed")
	}
	for range 100 {
		g.Upsert("shared.example.", a, testBitmap(1), 60, now)
	}
	if len(g.kernel.pending) != 1 {
		t.Fatal("retry queue did not coalesce")
	}
	g.kernel.update = fake.update
	g.retryProjection(now.Add(time.Second))
	if len(g.kernel.pending) != 0 || !g.Verify("shared.example.", a).KernelCovered {
		t.Fatal("retry did not publish desired bitmap")
	}
	g.kernel.remove = func(netip.Addr) error { return failure }
	g.Upsert("b.example.", b, testBitmap(2), 120, now)
	if fake.has(b) || !fake.has(a) || len(g.kernel.resident) != 1 || len(g.kernel.pending) != 2 {
		t.Fatal("failed removal freed an occupied slot")
	}
	g.kernel.remove = fake.remove
	g.retryProjection(now.Add(2 * time.Second))
	if fake.has(a) || !fake.has(b) || len(g.kernel.pending) != 0 {
		t.Fatal("replacement did not recover")
	}
	checkInvariants(t, g, fake)
}

func TestDomainProjectionForceAndFailedFork(t *testing.T) {
	old, fake := newTestRegistry(1, time.Minute)
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	old.Upsert("a.example.", ip, testBitmap(0), 60, now)
	clear(fake.bump)
	clear(fake.routing)
	if err := old.rebuildProjection(now); err != nil || !fake.has(ip) {
		t.Fatal("explicit rebuild skipped unchanged bits", err)
	}
	old.Start()
	t.Cleanup(func() { _ = old.Close() })
	failure := errors.New("candidate map unavailable")
	next := newDomainRegistry(1, time.Minute, func(netip.Addr, []uint32, []uint32) error { return failure }, fake.remove)
	if err := next.ForkFrom(old, func(string) []uint32 { return testBitmap(1) }, now); !errors.Is(err, failure) {
		t.Fatalf("fork error = %v", err)
	}
	if old.activity.registry != old {
		t.Fatal("rejected candidate stole activity ownership")
	}
	select {
	case <-old.workerDone:
		t.Fatal("predecessor worker was not resumed")
	default:
	}
	old.activity.observe(ip, "a.example.", now.Add(time.Minute))
	if !old.retention("a.example.", ip).After(now.Add(time.Minute)) {
		t.Fatal("predecessor lost retained activity")
	}
}
