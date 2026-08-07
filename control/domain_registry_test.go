/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeKernelDomainMaps records what the registry pushed to the kernel domain
// maps, keyed by IP. A present key means the IP is in both maps.
type fakeKernelDomainMaps struct {
	bump    map[netip.Addr][]uint32
	routing map[netip.Addr][]uint32
}

func newFakeKernelDomainMaps() *fakeKernelDomainMaps {
	return &fakeKernelDomainMaps{
		bump:    make(map[netip.Addr][]uint32),
		routing: make(map[netip.Addr][]uint32),
	}
}

func (f *fakeKernelDomainMaps) update(ip netip.Addr, bump, routing []uint32) {
	f.bump[ip] = append([]uint32(nil), bump...)
	f.routing[ip] = append([]uint32(nil), routing...)
}

func (f *fakeKernelDomainMaps) remove(ip netip.Addr) {
	delete(f.bump, ip)
	delete(f.routing, ip)
}

func (f *fakeKernelDomainMaps) has(ip netip.Addr) bool {
	_, ok := f.bump[ip]
	return ok
}

func testBitmap(rules ...int) []uint32 {
	b := make([]uint32, domainBitmapWords())
	for _, r := range rules {
		b[r/32] |= 1 << (r % 32)
	}
	return b
}

func bitmapHas(b []uint32, rule int) bool {
	return b != nil && b[rule/32]>>(rule%32)&1 == 1
}

func newTestRegistry(kernelMax, userMax int, minTTL time.Duration) (*DomainRegistry, *fakeKernelDomainMaps) {
	fake := newFakeKernelDomainMaps()
	g := newDomainRegistry(kernelMax, userMax, minTTL)
	g.update = fake.update
	g.remove = fake.remove
	return g, fake
}

// checkInvariants verifies the structural invariants of the registry and its
// agreement with the fake kernel maps.
func checkInvariants(t *testing.T, g *DomainRegistry, fake *fakeKernelDomainMaps) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.byIP) > g.kernelMax {
		t.Errorf("kernel occupancy %v exceeds hard limit %v", len(g.byIP), g.kernelMax)
	}
	if len(g.kernelIPHeap) != len(g.byIP) {
		t.Errorf("kernelIPHeap len %v != byIP len %v", len(g.kernelIPHeap), len(g.byIP))
	}
	inKernel := 0
	for qi, m := range g.byName {
		for ip, r := range m {
			if r.verifyHeapIdx < 0 || r.verifyHeapIdx >= g.verifyHeap.Len() || g.verifyHeap.items[r.verifyHeapIdx] != r {
				t.Errorf("%v/%v: bad verifyHeapIdx %v", qi.qname, ip, r.verifyHeapIdx)
			}
			if r.inKernel {
				inKernel++
				if r.kernelHeapIdx < 0 || r.kernelHeapIdx >= g.kernelHeap.Len() || g.kernelHeap.items[r.kernelHeapIdx] != r {
					t.Errorf("%v/%v: bad kernelHeapIdx %v", qi.qname, ip, r.kernelHeapIdx)
				}
				s := g.byIP[ip]
				if s == nil {
					t.Errorf("%v/%v: in-kernel registration without ipKernelState", qi.qname, ip)
				} else if _, ok := s.refs[r]; !ok {
					t.Errorf("%v/%v: in-kernel registration missing from refs", qi.qname, ip)
				}
			}
			if _, ok := g.byAddr[ip][r]; !ok {
				t.Errorf("%v/%v: registration missing from byAddr", qi.qname, ip)
			}
		}
	}
	if g.kernelHeap.Len() != inKernel {
		t.Errorf("kernelHeap len %v != in-kernel registrations %v", g.kernelHeap.Len(), inKernel)
	}
	if g.verifyHeap.Len() != g.size {
		t.Errorf("verifyHeap len %v != size %v", g.verifyHeap.Len(), g.size)
	}
	for ip, s := range g.byIP {
		if len(s.refs) == 0 {
			t.Errorf("%v: ipKernelState with no refs", ip)
		}
		if s.ip != ip {
			t.Errorf("%v: ipKernelState stores mismatched IP %v", ip, s.ip)
		}
		if s.heapIdx < 0 || s.heapIdx >= len(g.kernelIPHeap) || g.kernelIPHeap[s.heapIdx] != s {
			t.Errorf("%v: bad kernel IP heap index %v", ip, s.heapIdx)
		}
		// Recompute the flushed bitmaps from scratch.
		bump := make([]uint32, domainBitmapWords())
		routing := make([]uint32, domainBitmapWords())
		first := true
		var expiry time.Time
		for r := range s.refs {
			if first {
				expiry = r.expiry
			} else {
				expiry = combineKernelIPExpiry(expiry, r.expiry)
			}
			for w, bits := range r.bitmap {
				bump[w] |= bits
				if first {
					routing[w] = bits
				} else {
					routing[w] &= bits
				}
			}
			first = false
		}
		if !s.expiry.Equal(expiry) {
			t.Errorf("%v: IP expiry priority %v != recomputed priority %v", ip, s.expiry, expiry)
		}
		if !slices.Equal(fake.bump[ip], bump) {
			t.Errorf("%v: kernel bump %v, recomputed %v", ip, fake.bump[ip], bump)
		}
		if !slices.Equal(fake.routing[ip], routing) {
			t.Errorf("%v: kernel routing %v, recomputed %v", ip, fake.routing[ip], routing)
		}
	}
	for ip := range fake.bump {
		if g.byIP[ip] == nil {
			t.Errorf("%v: in kernel maps but not in byIP", ip)
		}
	}
}

func TestDomainRegistryUpsertFlushesKernel(t *testing.T) {
	g, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	qi := queryInfo{qname: "example.com.", qtype: 1}
	ip := netip.MustParseAddr("1.1.1.1")

	g.Upsert(qi, ip, testBitmap(0), 60, now)
	if !bitmapHas(fake.bump[ip], 0) || !bitmapHas(fake.routing[ip], 0) {
		t.Fatalf("single matching domain should set bump and routing bit 0: bump=%v routing=%v", fake.bump[ip], fake.routing[ip])
	}
	if got := g.Lookup(qi); len(got) != 1 || got[0] != ip {
		t.Fatalf("Lookup: got %v", got)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistrySharedIpBitmaps(t *testing.T) {
	g, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	ip := netip.MustParseAddr("1.1.1.1")
	qi1 := queryInfo{qname: "a.com.", qtype: 1}
	qi2 := queryInfo{qname: "b.com.", qtype: 1}

	// Two domains share one IP; only a.com. matches rule 0.
	g.Upsert(qi1, ip, testBitmap(0), 60, now)
	// b.com. was learned 50s ago: its expiry (now+10s) is earlier than
	// a.com.'s (now+60s).
	g.Upsert(qi2, ip, testBitmap(1), 60, now.Add(-50*time.Second))

	// bump: both rules hit (any domain matches). routing: none (not all
	// domains match either rule).
	if !bitmapHas(fake.bump[ip], 0) || !bitmapHas(fake.bump[ip], 1) {
		t.Fatalf("bump should have bits 0 and 1: %v", fake.bump[ip])
	}
	if bitmapHas(fake.routing[ip], 0) || bitmapHas(fake.routing[ip], 1) {
		t.Fatalf("routing should have no bits: %v", fake.routing[ip])
	}

	// Expire b.com. from the kernel: a.com. becomes the only contributor, so
	// routing bit 0 appears.
	g.Sweep(now.Add(11 * time.Second))
	if !bitmapHas(fake.routing[ip], 0) || bitmapHas(fake.routing[ip], 1) {
		t.Fatalf("routing should have only bit 0 after partial expiry: %v", fake.routing[ip])
	}
	// The expired registration still verifies in userspace.
	if got := g.Lookup(qi2); len(got) != 1 {
		t.Fatalf("expired-in-kernel registration should still verify: %v", got)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryKernelHardCap(t *testing.T) {
	g, fake := newTestRegistry(1, 16, 10*time.Second)
	now := time.Now()
	qi1 := queryInfo{qname: "a.com.", qtype: 1}
	qi2 := queryInfo{qname: "b.com.", qtype: 1}
	ip1 := netip.MustParseAddr("1.1.1.1")
	ip2 := netip.MustParseAddr("2.2.2.2")

	g.Upsert(qi1, ip1, testBitmap(0), 60, now)
	// Kernel is full; ip2 has the later expiry, so admitting it evicts
	// ip1 (earliest expiry) from the kernel only.
	g.Upsert(qi2, ip2, testBitmap(0), 60, now.Add(time.Second))
	if fake.has(ip1) || !fake.has(ip2) {
		t.Fatalf("ip1 should be kernel-evicted, ip2 admitted: bump=%v", fake.bump)
	}
	// The evicted record survives in userspace.
	if got := g.Lookup(qi1); len(got) != 1 || got[0] != ip1 {
		t.Fatalf("kernel-evicted record should stay in userspace: %v", got)
	}
	checkInvariants(t, g, fake)

	// Refreshing the evicted domain re-admits it, evicting ip2 in turn.
	g.Upsert(qi1, ip1, testBitmap(0), 60, now.Add(2*time.Second))
	if !fake.has(ip1) || fake.has(ip2) {
		t.Fatalf("refresh should re-admit ip1 and evict ip2: bump=%v", fake.bump)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryKernelHardCapRejectsEarlierIncomingIP(t *testing.T) {
	g, fake := newTestRegistry(1, 16, time.Second)
	now := time.Now()
	residentIP := netip.MustParseAddr("1.1.1.1")
	incomingIP := netip.MustParseAddr("2.2.2.2")

	g.Upsert(queryInfo{qname: "resident.com.", qtype: 1}, residentIP, testBitmap(0), 100, now)
	g.Upsert(queryInfo{qname: "incoming.com.", qtype: 1}, incomingIP, testBitmap(1), 10, now)

	if !fake.has(residentIP) || fake.has(incomingIP) {
		t.Fatalf("earlier-expiring incoming IP must not displace resident: %v", fake.bump)
	}
	if got := g.Lookup(queryInfo{qname: "incoming.com.", qtype: 1}); len(got) != 1 {
		t.Fatalf("rejected incoming IP should remain in userspace: %v", got)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryKernelHardCapEvictsCompleteIPState(t *testing.T) {
	g, fake := newTestRegistry(2, 16, time.Second)
	now := time.Now()
	sharedIP := netip.MustParseAddr("1.1.1.1")
	otherIP := netip.MustParseAddr("2.2.2.2")
	incomingIP := netip.MustParseAddr("3.3.3.3")
	qa := queryInfo{qname: "a.com.", qtype: 1}
	qb := queryInfo{qname: "b.com.", qtype: 1}

	// The shared IP is the earliest-expiring complete state. Capacity eviction
	// may choose it, but must not strip only a.com. and leave a misleading
	// partial bitmap behind.
	g.Upsert(qa, sharedIP, testBitmap(0), 10, now)
	g.Upsert(qb, sharedIP, testBitmap(1), 100, now)
	g.Upsert(queryInfo{qname: "other.com.", qtype: 1}, otherIP, testBitmap(2), 20, now)
	g.Upsert(queryInfo{qname: "incoming.com.", qtype: 1}, incomingIP, testBitmap(3), 50, now)

	if fake.has(sharedIP) || !fake.has(otherIP) || !fake.has(incomingIP) {
		t.Fatalf("the complete earliest-expiring IP state should be evicted: %v", fake.bump)
	}
	if g.byName[qa][sharedIP].inKernel || g.byName[qb][sharedIP].inKernel {
		t.Fatalf("all shared IP registrations must be evicted from kernel together")
	}
	if got := g.Lookup(qa); len(got) != 1 || got[0] != sharedIP {
		t.Fatalf("kernel-evicted shared IP must remain in userspace: %v", got)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryKernelHardCapReadmitsCompleteIPState(t *testing.T) {
	g, fake := newTestRegistry(1, 16, time.Second)
	now := time.Now()
	sharedIP := netip.MustParseAddr("1.1.1.1")
	otherIP := netip.MustParseAddr("2.2.2.2")
	qa := queryInfo{qname: "a.com.", qtype: 1}
	qb := queryInfo{qname: "b.com.", qtype: 1}

	g.Upsert(qa, sharedIP, testBitmap(0), 10, now)
	g.Upsert(qb, sharedIP, testBitmap(1), 100, now)
	g.Upsert(queryInfo{qname: "other.com.", qtype: 1}, otherIP, testBitmap(2), 50, now)
	if fake.has(sharedIP) {
		t.Fatalf("shared IP should initially be capacity-evicted")
	}

	// Refreshing either registration reconsiders every still-live
	// registration for the IP, so it cannot re-enter with a partial bitmap.
	g.Upsert(qa, sharedIP, testBitmap(0), 100, now.Add(60*time.Second))
	if !fake.has(sharedIP) || fake.has(otherIP) {
		t.Fatalf("shared IP should be re-admitted as a complete state: %v", fake.bump)
	}
	if !g.byName[qa][sharedIP].inKernel || !g.byName[qb][sharedIP].inKernel {
		t.Fatalf("all live shared-IP registrations must be re-admitted together")
	}
	if bitmapHas(fake.routing[sharedIP], 0) || bitmapHas(fake.routing[sharedIP], 1) {
		t.Fatalf("re-admitted shared IP should remain ambiguous: %v", fake.routing[sharedIP])
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryUserSoftCap(t *testing.T) {
	g, fake := newTestRegistry(16, 2, 10*time.Second)
	now := time.Now()
	ip := func(b byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, 0, b}) }
	qi := func(s string) queryInfo { return queryInfo{qname: s, qtype: 1} }

	// Three live registrations exceed the soft limit: nothing may be
	// evicted because none has expired.
	for i, name := range []string{"a.com.", "b.com.", "c.com."} {
		g.Upsert(qi(name), ip(byte(i+1)), testBitmap(0), 60, now)
	}
	if g.Size() != 3 {
		t.Fatalf("live registrations must survive the soft limit: size=%v", g.Size())
	}

	// Once expired, the earliest-expiring registrations are reclaimed on the
	// update path.
	past := now.Add(200 * time.Second)
	g.Upsert(qi("d.com."), ip(4), testBitmap(0), 60, past)
	if g.Size() > 2 {
		t.Fatalf("expired registrations should be reclaimed over the soft limit: size=%v", g.Size())
	}
	if got := g.Lookup(qi("a.com.")); len(got) != 0 {
		t.Fatalf("registration reclaimed by memory-pressure GC must be gone: %v", got)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryUserSoftCapGcOnRefresh(t *testing.T) {
	g, fake := newTestRegistry(16, 2, 10*time.Second)
	now := time.Now()
	ip := func(b byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, 0, b}) }
	qi := func(s string) queryInfo { return queryInfo{qname: s, qtype: 1} }

	for i, name := range []string{"a.com.", "b.com.", "c.com."} {
		g.Upsert(qi(name), ip(byte(i+1)), testBitmap(0), 60, now)
	}
	if g.Size() != 3 {
		t.Fatalf("live registrations must be allowed over the soft limit: %v", g.Size())
	}

	// Refreshing only an existing hot record must still reclaim other records
	// that have since passed expiry while the registry is over its cap.
	past := now.Add(200 * time.Second)
	g.Upsert(qi("c.com."), ip(3), testBitmap(0), 60, past)
	if g.Size() != 2 {
		t.Fatalf("refresh-path GC should restore the soft limit: %v", g.Size())
	}
	if got := g.Lookup(qi("a.com.")); len(got) != 0 {
		t.Fatalf("oldest expired registration should be reclaimed: %v", got)
	}
	if got := g.Lookup(qi("c.com.")); len(got) != 1 {
		t.Fatalf("refreshed live registration must survive GC: %v", got)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistrySweepLifetimes(t *testing.T) {
	g, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	qi := queryInfo{qname: "a.com.", qtype: 1}
	ip := netip.MustParseAddr("1.1.1.1")
	g.Upsert(qi, ip, testBitmap(0), 1, now)

	// After expiry (ttl clamped to minTTL) the kernel entry is
	// reaped but the userspace record survives.
	g.Sweep(now.Add(11 * time.Second))
	if fake.has(ip) {
		t.Fatalf("kernel entry should be reaped after expiry")
	}
	if got := g.Lookup(qi); len(got) != 1 {
		t.Fatalf("userspace record should survive kernel expiry")
	}

	// Expiry passing is NOT a removal: under the soft limit the sweep
	// never reaps userspace registrations (stale kernel bitmaps cost routing
	// performance, stale userspace records cost only memory).
	g.Sweep(now.Add(101 * time.Second))
	if got := g.Lookup(qi); len(got) != 1 {
		t.Fatalf("registration must survive its expiry; only memory-pressure GC may remove it")
	}
	if g.Size() != 1 {
		t.Fatalf("size should stay 1, got %v", g.Size())
	}

	// Memory-pressure GC reclaims it (most-stale-first).
	g.gcUser(now.Add(101 * time.Second))
	// userMax is 16 and size 1: under the limit, nothing is reclaimed even
	// when stale.
	if g.Size() != 1 {
		t.Fatalf("gcUser must not reclaim below the soft limit: size=%v", g.Size())
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistrySweepGcUser(t *testing.T) {
	g, fake := newTestRegistry(16, 2, 10*time.Second)
	now := time.Now()
	ip := func(b byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, 0, b}) }
	qi := func(s string) queryInfo { return queryInfo{qname: s, qtype: 1} }

	// Three live registrations sit over the soft limit; stagger their
	// expiries so the reclamation order is deterministic.
	g.Upsert(qi("a.com."), ip(1), testBitmap(0), 60, now)
	g.Upsert(qi("b.com."), ip(2), testBitmap(0), 60, now.Add(time.Second))
	g.Upsert(qi("c.com."), ip(3), testBitmap(0), 60, now.Add(2*time.Second))
	if g.Size() != 3 {
		t.Fatalf("live registrations must be allowed over the soft limit: %v", g.Size())
	}

	// All expired, no insert happening: the periodic sweep must reclaim the
	// most stale ones until the registry is back at the soft limit.
	g.Sweep(now.Add(200 * time.Second))
	if g.Size() != 2 {
		t.Fatalf("sweep should run memory-pressure GC on an idle registry: size=%v", g.Size())
	}
	if got := g.Lookup(qi("a.com.")); len(got) != 0 {
		t.Fatalf("oldest expired registration should be reclaimed by the sweep: %v", got)
	}
	if got := g.Lookup(qi("b.com.")); len(got) != 1 {
		t.Fatalf("newer registrations must survive the sweep: %v", got)
	}
	if got := g.Lookup(qi("c.com.")); len(got) != 1 {
		t.Fatalf("newer registrations must survive the sweep: %v", got)
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryNoExpiryLifecycle(t *testing.T) {
	g, fake := newTestRegistry(1, 1, 10*time.Second)
	now := time.Now()
	finiteQI := queryInfo{qname: "finite.com.", qtype: 1}
	permanentQI := queryInfo{qname: "resolver.example.", qtype: 1}
	sharedFiniteQI := queryInfo{qname: "shared-finite.com.", qtype: 1}
	otherQI := queryInfo{qname: "other.com.", qtype: 1}
	finiteIP := netip.MustParseAddr("1.1.1.1")
	permanentIP := netip.MustParseAddr("2.2.2.2")
	otherIP := netip.MustParseAddr("3.3.3.3")

	g.Upsert(finiteQI, finiteIP, testBitmap(0), 60, now)
	g.UpsertNoExpiry(permanentQI, permanentIP, testBitmap(0), now)
	if fake.has(finiteIP) || !fake.has(permanentIP) {
		t.Fatalf("no-expiry IP should outrank a finite resident at capacity: %v", fake.bump)
	}
	r := g.byName[permanentQI][permanentIP]
	if r == nil || !r.expiry.IsZero() {
		t.Fatalf("no-expiry registration should use zero deadlines: %+v", r)
	}

	// Neither an ordinary refresh nor a later finite incoming IP may replace
	// the no-expiry lease. A finite alias sharing the same IP must not lower
	// the complete IP state's capacity priority either.
	g.Upsert(permanentQI, permanentIP, testBitmap(0), 1, now.Add(time.Second))
	g.Upsert(sharedFiniteQI, permanentIP, testBitmap(1), 1, now.Add(time.Second))
	g.Upsert(otherQI, otherIP, testBitmap(0), 3600, now.Add(time.Second))
	if !g.byName[permanentQI][permanentIP].expiry.IsZero() {
		t.Fatal("finite refresh must not downgrade an existing no-expiry lease")
	}
	if !fake.has(permanentIP) || fake.has(otherIP) {
		t.Fatalf("finite IP must not evict a no-expiry resident: %v", fake.bump)
	}

	farFuture := now.Add(100 * 365 * 24 * time.Hour)
	g.Sweep(farFuture)
	if !fake.has(permanentIP) {
		t.Fatal("sweeper must not reap a no-expiry kernel registration")
	}
	g.gcUser(farFuture)
	if g.Size() != 1 || len(g.Lookup(permanentQI)) != 1 {
		t.Fatalf("memory-pressure GC should retain only the no-expiry registration: size=%v", g.Size())
	}
	checkInvariants(t, g, fake)

	// Hot reload carries the no-expiry semantic instead of converting it into
	// a finite deadline.
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	next, _ := newTestRegistry(1, 1, 10*time.Second)
	next.update = fake.update
	next.remove = fake.remove
	next.AdoptFrom(g, func(string) []uint32 { return testBitmap(0) }, farFuture)
	adopted := next.byName[permanentQI][permanentIP]
	if adopted == nil || !adopted.expiry.IsZero() || !fake.has(permanentIP) {
		t.Fatalf("adoption should preserve the no-expiry registration: %+v", adopted)
	}
	next.Sweep(farFuture.Add(100 * 365 * 24 * time.Hour))
	if !fake.has(permanentIP) {
		t.Fatal("adopted no-expiry registration must survive future sweeps")
	}
	checkInvariants(t, next, fake)
}

func TestDomainRegistryBitmapChange(t *testing.T) {
	g, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	qi := queryInfo{qname: "a.com.", qtype: 1}
	ip := netip.MustParseAddr("1.1.1.1")

	g.Upsert(qi, ip, testBitmap(0), 60, now)
	// Rules changed: the same domain now matches rule 1 instead of rule 0.
	g.Upsert(qi, ip, testBitmap(1), 60, now)
	if bitmapHas(fake.bump[ip], 0) || !bitmapHas(fake.bump[ip], 1) {
		t.Fatalf("bitmap change should move the contribution to rule 1: %v", fake.bump[ip])
	}
	checkInvariants(t, g, fake)

	// And to no rule at all: the kernel entry must be deleted while the
	// userspace record survives for verification.
	g.Upsert(qi, ip, testBitmap(), 60, now)
	if fake.has(ip) {
		t.Fatalf("zero bitmap should delete the kernel entry")
	}
	if got := g.Lookup(qi); len(got) != 1 {
		t.Fatalf("zero-bitmap record should stay in userspace")
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryAdoptFrom(t *testing.T) {
	old, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	oldBitmaps := map[string][]uint32{
		"a.com.": testBitmap(0),
		"b.com.": testBitmap(1),
		"c.com.": testBitmap(0),
		"d.com.": testBitmap(2),
		"e.com.": testBitmap(), // never enters the kernel
	}
	ip1 := netip.MustParseAddr("1.1.1.1")
	ip2 := netip.MustParseAddr("2.2.2.2")
	ip4 := netip.MustParseAddr("4.4.4.4")
	ip5 := netip.MustParseAddr("5.5.5.5")
	mustOld := func(name string, ip netip.Addr) {
		t.Helper()
		old.Upsert(queryInfo{qname: name, qtype: 1}, ip, oldBitmaps[name], 60, now)
	}
	mustOld("a.com.", ip1)
	mustOld("b.com.", ip1) // shares ip1
	mustOld("c.com.", ip2)
	mustOld("d.com.", ip4)
	mustOld("e.com.", ip5)

	// New rules: a.com. -> rule 0, b.com. -> nothing, c.com. -> rule 0,
	// d.com. -> nothing.
	newMatch := func(fqdn string) []uint32 {
		switch fqdn {
		case "a.com.":
			return testBitmap(0)
		case "c.com.":
			return testBitmap(0)
		default:
			return testBitmap()
		}
	}
	next, _ := newTestRegistry(16, 16, 10*time.Second)
	// The adopted registry writes the SAME (shared) fake maps.
	next.update = fake.update
	next.remove = fake.remove
	// The old plane is retired before adoption.
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	next.AdoptFrom(old, newMatch, now)

	// ip1: only a.com. contributes now -> routing bit 0 set.
	if !bitmapHas(fake.routing[ip1], 0) || bitmapHas(fake.bump[ip1], 1) {
		t.Fatalf("ip1 should keep only rule 0 after adoption: bump=%v routing=%v", fake.bump[ip1], fake.routing[ip1])
	}
	if !bitmapHas(fake.routing[ip2], 0) {
		t.Fatalf("ip2 should keep rule 0 after adoption")
	}
	// ip4 matched nothing under the new rules: its kernel entry must be
	// deleted.
	if fake.has(ip4) {
		t.Fatalf("ip4 should be deleted from the kernel maps after adoption")
	}
	// Userspace keeps every record (superset), including ip4 and the
	// zero-bitmap ip5.
	for name, ip := range map[string]netip.Addr{"d.com.": ip4, "e.com.": ip5} {
		if got := next.Lookup(queryInfo{qname: name, qtype: 1}); len(got) != 1 || got[0] != ip {
			t.Fatalf("%v should survive adoption in userspace: %v", name, got)
		}
	}
	if !next.Adopted() {
		t.Fatalf("registry should report adopted state")
	}
	checkInvariants(t, next, fake)

	// Expirations are carried over, not extended; records adopted with an
	// already-stale expiry are kept while the registry is under its
	// soft limit (and are the first reclamation candidates under memory
	// pressure).
	for _, r := range next.byName[queryInfo{qname: "a.com.", qtype: 1}] {
		if !r.expiry.Equal(now.Add(60 * time.Second)) {
			t.Fatalf("adoption must carry the original expiry: %v", r.expiry)
		}
	}
}

func TestDomainRegistryAdoptFromGcUser(t *testing.T) {
	old, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	ip := func(b byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, 0, b}) }
	qi := func(s string) queryInfo { return queryInfo{qname: s, qtype: 1} }

	old.Upsert(qi("a.com."), ip(1), testBitmap(0), 60, now)
	old.Upsert(qi("b.com."), ip(2), testBitmap(0), 60, now.Add(time.Second))
	old.Upsert(qi("c.com."), ip(3), testBitmap(0), 60, now.Add(2*time.Second))
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	// Adopt after every record has expired, into a plane whose soft limit
	// is 2: the most stale registration is reclaimed during adoption
	// instead of lingering until the first insert.
	next, _ := newTestRegistry(16, 2, 10*time.Second)
	next.update = fake.update
	next.remove = fake.remove
	next.AdoptFrom(old, func(string) []uint32 { return testBitmap(0) }, now.Add(200*time.Second))
	if next.Size() != 2 {
		t.Fatalf("adoption should reclaim expired registrations over the soft limit: size=%v", next.Size())
	}
	if got := next.Lookup(qi("a.com.")); len(got) != 0 {
		t.Fatalf("oldest expired registration should not survive adoption over the soft limit: %v", got)
	}
	if got := next.Lookup(qi("b.com.")); len(got) != 1 {
		t.Fatalf("newer registrations must survive adoption: %v", got)
	}
	if got := next.Lookup(qi("c.com.")); len(got) != 1 {
		t.Fatalf("newer registrations must survive adoption: %v", got)
	}
	checkInvariants(t, next, fake)
}

func TestDomainRegistryAdoptFromKernelCap(t *testing.T) {
	old, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	ip1 := netip.MustParseAddr("1.1.1.1")
	ip2 := netip.MustParseAddr("2.2.2.2")
	old.Upsert(queryInfo{qname: "a.com.", qtype: 1}, ip1, testBitmap(0), 60, now)
	old.Upsert(queryInfo{qname: "b.com.", qtype: 1}, ip2, testBitmap(0), 60, now.Add(time.Second))

	// The new plane's kernel table is smaller: only the IP with the latest
	// expiry survives adoption in the kernel.
	next, _ := newTestRegistry(1, 16, 10*time.Second)
	next.update = fake.update
	next.remove = fake.remove
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	next.AdoptFrom(old, func(string) []uint32 { return testBitmap(0) }, now)
	if fake.has(ip1) || !fake.has(ip2) {
		t.Fatalf("adoption should drop the earliest-expiring IP over the kernel cap: %v", fake.bump)
	}
	if got := next.Lookup(queryInfo{qname: "a.com.", qtype: 1}); len(got) != 1 {
		t.Fatalf("dropped IP should survive in userspace: %v", got)
	}
	checkInvariants(t, next, fake)
}

func TestDomainRegistryAdoptFromFreesCapacityBeforeInsert(t *testing.T) {
	old, fake := newTestRegistry(1, 16, 10*time.Second)
	now := time.Now()
	residentIP := netip.MustParseAddr("1.1.1.1")
	incomingIP := netip.MustParseAddr("2.2.2.2")
	old.Upsert(queryInfo{qname: "resident.com.", qtype: 1}, residentIP, testBitmap(0), 100, now)
	// This registration remains in userspace because its earlier expiry does
	// not justify displacing the resident IP from a full kernel map.
	old.Upsert(queryInfo{qname: "incoming.com.", qtype: 1}, incomingIP, testBitmap(0), 10, now)
	if !fake.has(residentIP) || fake.has(incomingIP) {
		t.Fatalf("test setup should leave only the resident IP in kernel: %v", fake.bump)
	}

	next, _ := newTestRegistry(1, 16, 10*time.Second)
	next.remove = fake.remove
	next.update = func(ip netip.Addr, bump, routing []uint32) {
		if !fake.has(ip) && len(fake.bump) >= 1 {
			t.Fatalf("attempted to insert %v before freeing the full kernel map", ip)
		}
		fake.update(ip, bump, routing)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	next.AdoptFrom(old, func(fqdn string) []uint32 {
		if fqdn == "incoming.com." {
			return testBitmap(0)
		}
		return testBitmap()
	}, now)

	if fake.has(residentIP) || !fake.has(incomingIP) {
		t.Fatalf("adoption should replace the obsolete resident at capacity: %v", fake.bump)
	}
	checkInvariants(t, next, fake)
}

func TestDomainRegistryAdoptFromPanics(t *testing.T) {
	now := time.Now()

	// Adopting into a non-empty registry must panic: a duplicated
	// (domain, ip) would silently corrupt the heap/index bookkeeping.
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("adoption into a non-empty registry should panic")
			}
		}()
		old, _ := newTestRegistry(16, 16, 10*time.Second)
		old.Upsert(queryInfo{qname: "a.com.", qtype: 1}, netip.MustParseAddr("1.1.1.1"), testBitmap(0), 60, now)
		_ = old.Close()
		next, _ := newTestRegistry(16, 16, 10*time.Second)
		next.Upsert(queryInfo{qname: "b.com.", qtype: 1}, netip.MustParseAddr("2.2.2.2"), testBitmap(0), 60, now)
		next.AdoptFrom(old, func(string) []uint32 { return testBitmap(0) }, now)
	}()

	// Adopting from a still-live registry must panic: its writers would
	// keep fighting the adopted state on the shared kernel maps.
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("adoption from a live registry should panic")
			}
		}()
		old, _ := newTestRegistry(16, 16, 10*time.Second)
		old.Upsert(queryInfo{qname: "a.com.", qtype: 1}, netip.MustParseAddr("1.1.1.1"), testBitmap(0), 60, now)
		next, _ := newTestRegistry(16, 16, 10*time.Second)
		next.AdoptFrom(old, func(string) []uint32 { return testBitmap(0) }, now)
	}()
}

func TestDomainRegistryClose(t *testing.T) {
	g, fake := newTestRegistry(16, 16, 10*time.Second)
	now := time.Now()
	qi := queryInfo{qname: "a.com.", qtype: 1}
	ip := netip.MustParseAddr("1.1.1.1")
	g.Upsert(qi, ip, testBitmap(0), 60, now)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	// Double close is fine, and mutations after close are no-ops (a retired
	// plane must not write the shared maps).
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g.Upsert(qi, netip.MustParseAddr("9.9.9.9"), testBitmap(1), 60, now)
	g.Sweep(now.Add(time.Hour))
	if g.Size() != 1 || !fake.has(ip) {
		t.Fatalf("mutations after Close must be no-ops: size=%v fake=%v", g.Size(), fake.bump)
	}
	// A closed registry can still be adopted from.
	next, _ := newTestRegistry(16, 16, 10*time.Second)
	next.update = fake.update
	next.remove = fake.remove
	next.AdoptFrom(g, func(string) []uint32 { return testBitmap(0) }, now)
	if got := next.Lookup(qi); len(got) != 1 {
		t.Fatalf("closed registry should remain adoptable: %v", got)
	}
}

// TestDomainRegistryConcurrent hammers the registry with concurrent upserts
// and sweeps, including the refresh-while-expiring interleaving that used to
// corrupt kernel routing state via a timer Reset race. Run with -race.
func TestDomainRegistryConcurrent(t *testing.T) {
	g, fake := newTestRegistry(64, 512, 20*time.Millisecond)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				qi := queryInfo{qname: fmt.Sprintf("d%v.com.", (w*i)%97), qtype: 1}
				ip := netip.AddrFrom4([4]byte{10, byte(w), byte(i >> 8), byte(i)})
				g.Upsert(qi, ip, testBitmap((w+i)%5), 1, time.Now())
			}
		}(w)
	}
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				g.Sweep(time.Now())
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()
	checkInvariants(t, g, fake)
	// A full sweep reaps every kernel contribution but keeps the userspace
	// registrations (they are only reclaimed by memory-pressure GC).
	g.Sweep(start.Add(time.Hour))
	checkInvariants(t, g, fake)
	if g.KernelSize() != 0 {
		t.Fatalf("all kernel entries should be reaped after a full sweep: %v", g.KernelSize())
	}
	if len(fake.bump) != 0 || len(fake.routing) != 0 {
		t.Fatalf("kernel maps should be empty after a full sweep")
	}
	// Force memory pressure: everything is stale, so gcUser reclaims all.
	g.gcUser(start.Add(time.Hour))
	// gcUser stops at the soft limit: with size possibly <= userMax already,
	// it only reclaims while size > userMax.
	if g.Size() > 512 {
		t.Fatalf("gcUser should bring size back under the soft limit: %v", g.Size())
	}
	checkInvariants(t, g, fake)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
}
