// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

// Exercise capture verdicts as shared-IP evidence expires, is capacity-evicted,
// and is promoted by ongoing traffic. Private maps/programs are never attached.
func TestDomainRetentionKernelIntegration(t *testing.T) {
	collection, state := routingKernelFixture(t, nil, 0, func(spec *ebpf.CollectionSpec) { spec.Maps["domain_routing_map"].MaxEntries = 1 })
	prepared := prepareFlowRulesForTest(t, "", "domain(full: target.example) && dport(443) -> direct(mark:37)")
	prepared.enableMITMPlan(mitmRoutingPlugin("target.example").Plan())
	matcher, _ := routingMatcherForTest(t, prepared)
	matcher.bpf = state
	if err := matcher.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	core := &controlPlaneCore{bpf: state}
	g := newDomainRegistry(int(state.DomainRoutingMap.MaxEntries()), 10*time.Second, core.writeDomainBitmaps, core.deleteDomainBitmaps)
	now := time.Now()
	a, b := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	domain := "target.example."
	g.Upsert(domain, a, matcher.domainMatcher.MatchDomainBitmap(domain), 60, now)
	g.Upsert("outside.example.", a, matcher.domainMatcher.MatchDomainBitmap("outside.example."), 10, now)
	g.Upsert(domain, b, matcher.domainMatcher.MatchDomainBitmap(domain), 50, now)
	// Start the verdict checks from a cold restore, with no inherited kernel
	// entries. The grouped baseline must rebuild the same complete-IP projection.
	dir := t.TempDir()
	g.EnablePersistence(dir)
	g.writeRenewals(now)
	for ip := range g.kernel.resident {
		core.deleteDomainBitmaps(ip)
	}
	g = newDomainRegistry(int(state.DomainRoutingMap.MaxEntries()), 10*time.Second, core.writeDomainBitmaps, core.deleteDomainBitmaps)
	if err := g.Restore(dir, matcher.domainMatcher.MatchDomainBitmap, now); err != nil {
		t.Fatal(err)
	}
	sequence := uint16(47000)
	check := func(label string, ip netip.Addr, port uint16, capture bool, outbound uint8, mark uint32) {
		t.Helper()
		for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
			for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
				sequence++ // no inherited UDP/TCP routing state between observations
				src := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), sequence)
				dst := netip.AddrPortFrom(ip, port)
				packet, ipProto := routingKernelPacket(src, dst, proto)
				want := ^uint32(0)
				if capture {
					want = 7
				}
				out := make([]byte, 256)
				verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), ContextOut: out, Repeat: 1})
				if err != nil || verdict != want {
					t.Fatalf("%s %s %d: verdict=%d want=%d err=%v", label, name, proto, verdict, want, err)
				}
				key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(port), L4proto: ipProto}
				key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), ip.As16()
				var result bpfRoutingResult
				err = lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &result)
				if !capture {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("%s created userspace state for direct: %+v %v", label, result, err)
					}
					if got := binary.NativeEndian.Uint32(out[8:12]); got != mark {
						t.Fatalf("%s %s %d: kernel-direct mark=%d, want %d", label, name, proto, got, mark)
					}
				} else if err != nil || result.Outbound != outbound || result.Mark != mark || result.Must != 0 || result.CaptureFlags != captureHTTP {
					t.Fatalf("%s changed capture policy: %+v %v", label, result, err)
				}
			}
		}
	}
	check("shared CDN", a, 443, true, uint8(consts.OutboundControlPlaneRouting), 0)
	check("capacity omission", b, 443, false, 0, 0)
	check("SSH", a, 22, false, 0, 0)
	check("unrelated HTTPS", netip.MustParseAddr("198.51.100.3"), 443, false, 0, 0)
	g.activity.observe(a, "unobserved.example.", now.Add(9*time.Second))
	g.Upsert(domain, a, matcher.domainMatcher.MatchDomainBitmap(domain), 1, now.Add(9*time.Second))
	g.Sweep(now.Add(9 * time.Second))
	check("unchanged observations preserve shared CDN", a, 443, true, uint8(consts.OutboundControlPlaneRouting), 0)
	// This name has no pair to extend. Collection of another pair still changes
	// the complete-IP projection, including the actual kernel capture decision.
	g.activity.observe(a, "unobserved.example.", now.Add(10*time.Second))
	check("zero pair GC", a, 443, true, uint8(consts.OutboundDirect), 37)
	g.activity.observe(b, "target.example", now.Add(49*time.Second))
	g.activity.enqueue(newDomainActivityKey(b, "target.example"), now.Add(58*time.Second))
	check("queued activity awaits projection publication", b, 443, false, 0, 0)
	g.Sweep(now.Add(58 * time.Second))
	check("traffic promoted omitted IP", b, 443, true, uint8(consts.OutboundDirect), 37)
	check("complete IP eviction", a, 443, false, 0, 0)
	if !g.Verify(domain, a).Paired {
		t.Fatal("capacity eviction destroyed verification evidence")
	}
	// Resident-only refresh must raise its cached priority without changing
	// capture. A later-delivered older observation must not evict that winner.
	g.activity.observe(b, "target.example", now.Add(59*time.Second))
	g.activity.observe(a, "target.example", now.Add(58500*time.Millisecond))
	check("refreshed resident keeps its slot", b, 443, true, uint8(consts.OutboundDirect), 37)
	check("lower-priority omitted refresh remains direct", a, 443, false, 0, 0)
	g.Sweep(now.Add(69 * time.Second))
	check("GC restored kernel direct", b, 443, false, 0, 0)
	if g.Verify(domain, b).Paired {
		t.Fatal("expired verification evidence survived GC")
	}

	// A rejected zero-rule witness must remove even a previously selected
	// positive projection. The spare kernel slot can serve a different bucket.
	c := a.Next()
	for domainCapacityBucket(c) == domainCapacityBucket(a) {
		c = c.Next()
	}
	at := now.Add(70 * time.Second)
	g.Upsert(domain, a, matcher.domainMatcher.MatchDomainBitmap(domain), 60, at)
	g.Upsert(domain, c, matcher.domainMatcher.MatchDomainBitmap(domain), 50, at)
	g.memoryLimit = g.memoryUsed
	check("before user-cap omission", a, 443, true, uint8(consts.OutboundDirect), 37)
	g.Upsert("outside.example.", a, matcher.domainMatcher.MatchDomainBitmap("outside.example."), 10, at)
	if u := g.Usage(); u.UserUsed != 2 || u.OmittedPairs != 1 || u.IncompleteBuckets != 1 ||
		!g.Verify(domain, a).Paired || g.Verify("outside.example.", a).Paired {
		t.Fatalf("unexpected cap state: %+v", u)
	}
	check("user-cap omitted zero witness", a, 443, false, 0, 0)
	check("non-colliding IP fills vacated slot", c, 443, true, uint8(consts.OutboundDirect), 37)
	g.Sweep(at.Add(10 * time.Second))
	check("user-cap omission expired", a, 443, true, uint8(consts.OutboundDirect), 37)
}
