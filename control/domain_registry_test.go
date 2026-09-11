// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
)

type fakeKernelDomainMaps struct {
	bump    map[netip.Addr][]uint32
	routing map[netip.Addr][]uint32
}

func newFakeKernelDomainMaps() *fakeKernelDomainMaps {
	return &fakeKernelDomainMaps{make(map[netip.Addr][]uint32), make(map[netip.Addr][]uint32)}
}
func (f *fakeKernelDomainMaps) update(ip netip.Addr, bump, routing []uint32) {
	f.bump[ip], f.routing[ip] = slices.Clone(bump), slices.Clone(routing)
}
func (f *fakeKernelDomainMaps) remove(ip netip.Addr)   { delete(f.bump, ip); delete(f.routing, ip) }
func (f *fakeKernelDomainMaps) has(ip netip.Addr) bool { _, ok := f.bump[ip]; return ok }
func testBitmap(rules ...int) []uint32 {
	b := make([]uint32, domainBitmapWords())
	for _, r := range rules {
		b[r/32] |= 1 << (r % 32)
	}
	return b
}
func bitmapHas(b []uint32, rule int) bool { return b != nil && b[rule/32]>>(rule%32)&1 == 1 }
func newTestRegistry(kernelMax int, window time.Duration) (*DomainRegistry, *fakeKernelDomainMaps) {
	fake := newFakeKernelDomainMaps()
	g := newDomainRegistry(kernelMax, window, fake.update, fake.remove)
	return g, fake
}
func newRoutingDomainRegistry() *DomainRegistry {
	g, _ := newTestRegistry(32, time.Second)
	return g
}
func (g *DomainRegistry) Upsert(name string, ip netip.Addr, bitmap []uint32, ttl int, now time.Time) {
	g.ObserveDNS(name, ip, bitmap, ttl, now)
}
func (g *DomainRegistry) Size() int { return g.Usage().UserUsed }
func (g *DomainRegistry) retention(name string, ip netip.Addr) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r := g.byName[name]; r != nil {
		return r.addresses[ip]
	}
	return time.Time{}
}
func checkInvariants(t *testing.T, g *DomainRegistry, fake *fakeKernelDomainMaps) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.byName {
		if len(r.addresses) == 0 {
			t.Fatal("empty name bucket")
		}
	}
	if len(g.kernel.resident) > g.kernel.max || len(fake.bump) != len(g.kernel.resident) || len(fake.routing) != len(g.kernel.resident) {
		t.Fatal("kernel occupancy mismatch")
	}
	for ip, s := range g.kernel.resident {
		var intersection []uint32
		union := testBitmap()
		for _, r := range g.byName {
			if _, exists := r.addresses[ip]; !exists {
				continue
			}
			if intersection == nil {
				intersection = slices.Clone(r.bitmap)
			}
			for i, bits := range r.bitmap {
				union[i] |= bits
				intersection[i] &= bits
			}
		}
		if domainBitmapAllZero(union) || !slices.Equal(union, fake.bump[ip]) || !slices.Equal(intersection, fake.routing[ip]) || !slices.Equal(s.bump, union) {
			t.Fatal("kernel does not contain complete shared-IP aggregate")
		}
	}
}

func TestDomainRoutingMapValueLayout(t *testing.T) {
	var value bpfDomainRouting
	bitmapBytes := uintptr(consts.MaxMatchSetLen / 8)
	if unsafe.Offsetof(value.Bump) != 0 || unsafe.Offsetof(value.Routing) != bitmapBytes || unsafe.Sizeof(value) != 2*bitmapBytes {
		t.Fatal("domain map layout mismatch")
	}
}

func TestDomainRetentionWindowAndGC(t *testing.T) {
	window := 7 * 24 * time.Hour
	now := time.Now()
	g, fake := newTestRegistry(1, window)
	ip := netip.MustParseAddr("192.0.2.1")
	name := "example.org."
	g.Upsert(name, ip, testBitmap(0), 60, now)
	if !g.retention(name, ip).Equal(now.Add(window)) {
		t.Fatal("window is not the TTL floor")
	}
	generation := g.generation
	for range 10 {
		g.Verify(name, ip)
	}
	if g.generation != generation || !g.retention(name, ip).Equal(now.Add(window)) {
		t.Fatal("verification refreshed evidence")
	}
	g.Upsert(name, ip, testBitmap(0), int((2*window)/time.Second), now)
	g.Upsert(name, ip, testBitmap(0), 1, now.Add(time.Hour))
	if !g.retention(name, ip).Equal(now.Add(2 * window)) {
		t.Fatal("shorter refresh reduced retention")
	}
	g.Sweep(now.Add(2*window - time.Second))
	if !g.Verify(name, ip).Paired || !fake.has(ip) {
		t.Fatal("collected too early")
	}
	g.Sweep(now.Add(2 * window))
	if g.Verify(name, ip).Registered || fake.has(ip) || g.Usage().GC != 1 {
		t.Fatal("deadline did not collect both indexes and kernel state")
	}
	g.activity.observe(ip, name, now.Add(2*window))
	if g.Size() != 0 {
		t.Fatal("traffic recreated DNS evidence")
	}
	checkInvariants(t, g, fake)
}

func TestDomainTrafficRefreshPrecision(t *testing.T) {
	for _, ip := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
		t.Run(ip.String(), func(t *testing.T) {
			now := time.Now()
			g, fake := newTestRegistry(2, time.Hour)
			a, b := "a.example.", "b.example."
			g.Upsert(a, ip, testBitmap(0), 1, now)
			g.Upsert(b, ip, testBitmap(), 1, now)
			g.activity.observe(ip, "A.EXAMPLE", now.Add(30*time.Minute))
			if !g.retention(a, ip).Equal(now.Add(90*time.Minute)) || !g.retention(b, ip).Equal(now.Add(time.Hour)) {
				t.Fatal("precise activity refreshed unrelated pair")
			}
			g.activity.observe(ip, "unknown.example", now.Add(40*time.Minute))
			if g.Size() != 2 || !g.retention(b, ip).Equal(now.Add(time.Hour)) {
				t.Fatal("unknown sniff created or broadly refreshed evidence")
			}
			g.activity.observe(ip, "", now.Add(50*time.Minute))
			if !g.retention(a, ip).Equal(now.Add(110*time.Minute)) || !g.retention(b, ip).Equal(now.Add(110*time.Minute)) {
				t.Fatal("IP activity did not refresh all pairs")
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestDomainVerificationAddressFamily(t *testing.T) {
	ip4, ip6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	for _, only := range []netip.Addr{ip4, ip6} {
		t.Run(only.String(), func(t *testing.T) {
			g, _ := newTestRegistry(2, time.Minute)
			now := time.Now()
			name := "dual.example."
			g.Upsert(name, only, testBitmap(0), 120, now)
			for _, destination := range []netip.Addr{ip4, ip6, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("::ffff:192.0.2.1")} {
				paired := destination.Unmap() == only
				want := DomainVerification{Registered: destination.Unmap().Is4() == only.Is4(), Paired: paired, KernelCovered: paired}
				if got := g.Verify(name, destination); got != want {
					t.Fatalf("destination %s: got %+v, want %+v", destination, got, want)
				}
			}
			// Both families share a name bucket, but each pair owns its deadline.
			other := ip4
			if only == ip4 {
				other = ip6
			}
			g.Upsert(name, other, testBitmap(0), 60, now)
			g.activity.observe(other, name, now.Add(30*time.Second))
			if !g.retention(name, other).Equal(now.Add(90*time.Second)) ||
				!g.retention(name, only).Equal(now.Add(120*time.Second)) {
				t.Fatal("named activity changed the other address family's retention")
			}
			g.Sweep(now.Add(90 * time.Second))
			if got := g.Verify(name, other); got != (DomainVerification{}) {
				t.Fatalf("other family still counts as registered after GC: %+v", got)
			}
			if got := g.Verify(name, only); got != (DomainVerification{true, true, true}) {
				t.Fatalf("GC removed the surviving family: %+v", got)
			}
		})
	}
}

func TestDomainActivityBeforeCollection(t *testing.T) {
	now := time.Now()
	g, _ := newTestRegistry(1, time.Minute)
	ip := netip.MustParseAddr("192.0.2.1")
	name := "example.org."
	g.Upsert(name, ip, testBitmap(0), 1, now)
	// A GC deadline is not DNS trust expiry. If activity wins the lock before
	// collection, retain the evidence still present according to the formula.
	g.activity.observe(ip, name, now.Add(61*time.Second))
	if !g.retention(name, ip).Equal(now.Add(121 * time.Second)) {
		t.Fatal("existing evidence was discarded before applying activity")
	}
	g.Sweep(now.Add(121 * time.Second))
	g.activity.observe(ip, name, now.Add(122*time.Second))
	if g.Size() != 0 {
		t.Fatal("activity recreated a collected pair")
	}
}

func TestDomainDelayedObservationDoesNotReviveCollectedEvidence(t *testing.T) {
	now := time.Now()
	g, fake := newTestRegistry(1, time.Minute)
	ip := netip.MustParseAddr("192.0.2.1")
	g.Upsert("delayed.example.", ip, testBitmap(0), 60, now)
	g.Sweep(now.Add(2 * time.Minute))
	// An observation can wait behind a newer event before acquiring the lock.
	g.Upsert("delayed.example.", ip, testBitmap(0), 60, now.Add(10*time.Second))
	if g.Size() != 0 || fake.has(ip) {
		t.Fatal("delayed observation revived already collected evidence")
	}
}

func TestDomainKernelRankingAndBackfill(t *testing.T) {
	now := time.Now()
	g, fake := newTestRegistry(1, time.Second)
	shared, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	g.Upsert("short.example.", shared, testBitmap(0), 10, now)
	g.Upsert("long.example.", shared, testBitmap(0, 1), 100, now)
	g.Upsert("zero.example.", shared, testBitmap(), 1000, now)
	g.Upsert("other.example.", other, testBitmap(1), 80, now)
	if !fake.has(shared) || fake.has(other) || !domainBitmapAllZero(fake.routing[shared]) {
		t.Fatal("ranking must use latest relevant deadline and complete AND")
	}
	if !g.Verify("other.example.", other).Paired {
		t.Fatal("capacity eviction destroyed evidence")
	}
	// Traffic to the omitted candidate promotes it and evicts the entire old IP.
	g.activity.observe(other, "other.example", now.Add(79*time.Second))
	g.Upsert("other.example.", other, testBitmap(1), 60, now.Add(79*time.Second))
	if !fake.has(other) || fake.has(shared) {
		t.Fatal("updated nonresident candidate was not admitted")
	}
	// A long-lived zero bitmap must not keep an IP ranked after its relevant
	// registrations expire. It still remains available for verification.
	g.Sweep(now.Add(101 * time.Second))
	if g.Usage().KernelCandidates != 1 || !g.Verify("zero.example.", shared).Paired {
		t.Fatal("irrelevant evidence changed candidate count")
	}
	checkInvariants(t, g, fake)

	g2, f2 := newTestRegistry(1, time.Second)
	g2.Upsert("first.", shared, testBitmap(0), 60, now)
	g2.Upsert("next.", other, testBitmap(1), 50, now)
	// Delete the higher-ranked name via elapsed time after the lower-ranked
	// candidate's retention has been extended by IP traffic.
	g2.activity.observe(other, "", now.Add(49*time.Second))
	g2.window = time.Minute
	g2.activity.observe(other, "", now.Add(49*time.Second))
	if !f2.has(other) {
		t.Fatal("activity did not reconsider omitted IP")
	}
	g2.Sweep(now.Add(61 * time.Second))
	checkInvariants(t, g2, f2)
}

func TestDomainSharedIPGCRecomputesAND(t *testing.T) {
	now := time.Now()
	g, fake := newTestRegistry(1, time.Second)
	ip := netip.MustParseAddr("192.0.2.1")
	g.Upsert("match.example.", ip, testBitmap(0), 20, now)
	g.Upsert("unrelated.example.", ip, testBitmap(), 10, now)
	if bitmapHas(fake.routing[ip], 0) {
		t.Fatal("zero evidence did not clear AND")
	}
	g.Sweep(now.Add(10 * time.Second))
	if !bitmapHas(fake.routing[ip], 0) {
		t.Fatal("expired pair still clears AND")
	}
	g.Sweep(now.Add(20 * time.Second))
	if fake.has(ip) {
		t.Fatal("empty IP retained")
	}
}

func TestVerifySniffReroutesCapacityEvictedPair(t *testing.T) {
	g, _ := newTestRegistry(0, time.Hour)
	ip := netip.MustParseAddr("192.0.2.1")
	g.Upsert("example.com.", ip, testBitmap(0), 1, time.Now())
	c := &ControlPlane{core: &controlPlaneCore{domainRegistry: g}, sniffVerifyMode: consts.SniffVerifyMode_Strict}
	verified, reroute, err := c.verifySniff(context.Background(), netip.AddrPortFrom(ip, 443), "example.com")
	if err != nil || !verified || !reroute {
		t.Fatalf("verification=%v reroute=%v error=%v", verified, reroute, err)
	}
}

func TestDomainRegistryUnboundedUserspace(t *testing.T) {
	g, fake := newTestRegistry(1, time.Hour)
	now := time.Now()
	for i := range 300 {
		g.Upsert(fmt.Sprintf("%d.example.", i), netip.MustParseAddr("192.0.2.1"), testBitmap(), 1, now)
	}
	if g.Size() != 300 || len(fake.bump) != 0 {
		t.Fatal("zero-only evidence was bounded or published")
	}
	checkInvariants(t, g, fake)
}

func TestDomainRegistryAdoptionAndActivityHandoff(t *testing.T) {
	now := time.Now()
	old, fake := newTestRegistry(1, time.Minute)
	ip := netip.MustParseAddr("192.0.2.1")
	name := "example.com."
	old.Upsert(name, ip, testBitmap(0), 1, now)
	activity := old.activity
	activity.prepareHandoff()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	activity.observe(ip, name, now.Add(100*time.Second))
	activity.observe(ip, name, now.Add(50*time.Second))
	if !old.retention(name, ip).Equal(now.Add(time.Minute)) {
		t.Fatal("retired registry was mutated")
	}
	next, _ := newTestRegistry(1, time.Minute)
	next.kernel.update, next.kernel.remove = fake.update, fake.remove
	next.AdoptFrom(old, func(string) []uint32 { return testBitmap(2) }, now.Add(120*time.Second))
	if !next.retention(name, ip).Equal(now.Add(160*time.Second)) || !bitmapHas(fake.routing[ip], 2) || bitmapHas(fake.bump[ip], 0) {
		t.Fatal("handoff lost evidence, deadlines or bitmap recomputation")
	}
	activity.observe(ip, name, now.Add(150*time.Second))
	if !next.retention(name, ip).Equal(now.Add(210 * time.Second)) {
		t.Fatal("surviving connection still targets old registry")
	}
	checkInvariants(t, next, fake)
}

func TestDomainRegistryConcurrent(t *testing.T) {
	g, fake := newTestRegistry(4, time.Hour)
	now := time.Now()
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(worker + 1)})
			name := fmt.Sprintf("%d.example.", worker)
			for range 20 {
				g.Upsert(name, ip, testBitmap(worker), 60, now)
				g.activity.observe(ip, name, now)
				g.Verify(name, ip)
				g.Sweep(now)
			}
		})
	}
	wg.Wait()
	checkInvariants(t, g, fake)
	if g.Size() != 8 {
		t.Fatal("lost concurrent evidence")
	}
}
