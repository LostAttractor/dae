// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestDomainCapacityReclaimsSparsePairIndexes(t *testing.T) {
	const fanout = 64
	g, kernel := newTestRegistry(fanout+1, time.Second)
	now := time.Now()
	hub := netip.MustParseAddr("192.0.2.1")
	const anchor = "anchor.example."
	g.Upsert(anchor, hub, testBitmap(0), 3600, now)
	r, s := g.byName[anchor], g.byIP[hub]
	pair := r.addresses[hub]
	baseline := g.memoryUsed
	for range 2 {
		ip := hub
		for i := range fanout {
			ip = ip.Next()
			g.Upsert(anchor, ip, testBitmap(0), i+1, now)
			g.Upsert(fmt.Sprintf("d%d.example.", i), hub, nil, i+1, now)
		}
		oldAddresses, oldDomains := r.addresses, s.domains
		// A succession of small collections must reclaim the old backing
		// just as one large collection does.
		for range fanout {
			now = now.Add(time.Second)
			g.Sweep(now)
		}
		delete(oldAddresses, hub)
		delete(oldDomains, r)
		if r.addresses[hub] != pair || s.domains[r] != pair || g.memoryUsed != baseline {
			t.Fatal("sparse indexes still use their old maps, lost the retained pair, or kept its old charge")
		}
		checkInvariants(t, g, kernel)
	}
}

func TestDomainCapacityIsolatesWholeIPs(t *testing.T) {
	g, kernel := newTestRegistry(4, 10*time.Second)
	g.activityLag = time.Second
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	bucket := domainCapacityBucket(ip)
	collision, other := ip.Next(), ip.Next()
	for domainCapacityBucket(collision) != bucket {
		collision = collision.Next()
	}
	for domainCapacityBucket(other) == bucket {
		other = other.Next()
	}
	g.Upsert("match.", ip, testBitmap(0), 100, now)
	g.Upsert("collision.", collision, testBitmap(1), 100, now)
	g.Upsert("other.", other, testBitmap(2), 20, now)
	g.memoryLimit = g.memoryUsed
	// Omission of even a zero-rule witness invalidates the whole IP.
	g.Upsert("zero.", ip, testBitmap(), 30, now)
	if u := g.Usage(); u.UserUsed != 3 || u.OmittedPairs != 1 || u.IncompleteBuckets != 1 || u.KernelCandidates != 1 ||
		kernel.has(ip) || kernel.has(collision) || !kernel.has(other) || !g.Verify("match.", ip).Paired || g.Verify("zero.", ip).Registered {
		t.Fatalf("incomplete projection or wrong verification: %+v", u)
	}
	g.Sweep(now.Add(21 * time.Second))
	g.Upsert("new.", ip, testBitmap(3), 100, now.Add(22*time.Second))
	if kernel.has(ip) || !g.Verify("new.", ip).Paired || g.Usage().UserUsed != 3 {
		t.Fatal("free capacity was confused with complete history")
	}
	// Exact known activity cannot be activity for the missing name; an
	// anonymous observation can. The lag still applies before resumption.
	g.activity.observe(ip, "match.", now.Add(28*time.Second))
	if !g.incomplete[bucket].Equal(now.Add(30 * time.Second)) {
		t.Fatal("known named activity extended unrelated missing evidence")
	}
	g.activity.observe(ip, "", now.Add(29*time.Second))
	g.Sweep(now.Add(39 * time.Second))
	if kernel.has(ip) || kernel.has(collision) {
		t.Fatal("bucket reopened before the observation grace elapsed")
	}
	g.Sweep(now.Add(40 * time.Second))
	if !kernel.has(ip) || !kernel.has(collision) || !domainBitmapAllZero(kernel.routing[ip]) || g.Usage().IncompleteBuckets != 0 {
		t.Fatal("expiry failed to restore the aggregate of all retained pairs")
	}
	checkInvariants(t, g, kernel)
}

func TestDomainCapacityFork(t *testing.T) {
	now := time.Now()
	old, _ := newTestRegistry(4, time.Minute)
	ip := netip.MustParseAddr("2001:db8::1")
	old.Upsert("first.", ip, testBitmap(0), 100, now)
	old.Upsert("second.", ip, testBitmap(1), 100, now)
	old.memoryLimit = old.memoryUsed
	old.Upsert("missing.", ip, nil, 90, now)
	match := func(string) []uint32 { return testBitmap(2) }
	small, _ := newTestRegistry(4, time.Minute)
	small.memoryLimit = old.memoryUsed - 1
	if err := small.ForkFrom(old, match, now); err == nil || old.activity.registry != old || old.Usage().UserUsed != 2 {
		t.Fatal("smaller limit silently discarded history or stole ownership")
	}
	next, kernel := newTestRegistry(4, time.Minute)
	next.memoryLimit = 2 * old.memoryUsed
	if err := next.ForkFrom(old, match, now); err != nil {
		t.Fatal(err)
	}
	next.Upsert("third.", ip, testBitmap(3), 100, now)
	if u := next.Usage(); u.MemoryLimit != next.memoryLimit || u.UserUsed != 3 || u.OmittedPairs != 1 || u.IncompleteBuckets != 1 || kernel.has(ip) {
		t.Fatalf("larger limit restored certainty: %+v", u)
	}
	checkInvariants(t, next, kernel)
}

func TestDomainCapacityForkRepricesHistory(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	old, _ := newTestRegistry(4, time.Minute)
	feed := new(testDomainDirect)
	old.direct = feed
	old.Upsert("target.", ip, nil, 1, now)
	old.Start()
	t.Cleanup(func() { _ = old.Close() })
	small, _ := newTestRegistry(4, time.Minute)
	small.memoryLimit = old.Usage().MemoryUsed
	if err := small.ForkFrom(old, func(string) []uint32 { return testBitmap(0) }, now); err == nil || !feed.running.Load() {
		t.Fatal("successor ignored the new bitmap cost or failed to resume the old reader")
	}
	old.Upsert("matched.", ip, testBitmap(0), 1, now)
	next, kernel := newTestRegistry(4, time.Minute)
	next.memoryLimit = old.Usage().MemoryUsed - domainIPBitmapMemory()
	if err := next.ForkFrom(old, func(string) []uint32 { return nil }, now); err != nil || feed.running.Load() {
		t.Fatal("a cheaper successor was rejected or the retired reader is running", err)
	}
	if !next.Verify("matched.", ip).Paired {
		t.Fatal("repricing lost DNS evidence")
	}
	checkInvariants(t, next, kernel)
}
