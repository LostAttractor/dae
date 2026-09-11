// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

// Exercise capture verdicts as shared-IP evidence expires, is capacity-evicted,
// and is promoted by ongoing traffic. Private maps/programs are never attached.
func TestDomainRetentionKernelIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF program tests")
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "lan_ingress_l2" && name != "tproxy_wan_egress_l2" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	spec.Maps["domain_routing_map"].MaxEntries = 1
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	state := &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{
		RoutingMap: collection.Maps["routing_map"], RoutingProfileMap: collection.Maps["routing_profile_map"],
		RoutingInterfaceMap: collection.Maps["routing_interface_map"], LpmArrayMap: collection.Maps["lpm_array_map"],
		UnusedLpmType: collection.Maps["unused_lpm_type"], DomainRoutingMap: collection.Maps["domain_routing_map"],
	}, bpfVariables: bpfVariables{DefaultRoutingProfile: collection.Variables["default_routing_profile"]}}}
	prepared := prepareFlowRulesForTest(t, "", "domain(full: target.example) && dport(443) -> direct(mark:37)")
	prepared.enableMITMPlan(mitmRoutingPlugin("target.example").Plan())
	matcher, builder := routingMatcherForTest(t, prepared)
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
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
	// entries. The grouped snapshot must rebuild the same complete-IP projection.
	path := filepath.Join(t.TempDir(), "domain-registry.json.gz")
	if err := g.Save(path); err != nil {
		t.Fatal(err)
	}
	for ip := range g.kernel.resident {
		core.deleteDomainBitmaps(ip)
	}
	g = newDomainRegistry(int(state.DomainRoutingMap.MaxEntries()), 10*time.Second, core.writeDomainBitmaps, core.deleteDomainBitmaps)
	if err := g.Restore(path, matcher.domainMatcher.MatchDomainBitmap, now); err != nil {
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
				verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
				if err != nil || verdict != want {
					t.Fatalf("%s %s %d: verdict=%d want=%d err=%v", label, name, proto, verdict, want, err)
				}
				key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(port), L4proto: ipProto}
				key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), ip.As16()
				var result bpfRoutingResult
				err = collection.Maps["routing_tuples_map"].Lookup(key, &result)
				if !capture {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("%s created userspace state for direct: %+v %v", label, result, err)
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
	g.Sweep(now.Add(10 * time.Second))
	check("zero pair GC", a, 443, true, uint8(consts.OutboundDirect), 37)
	g.activity.observe(b, "target.example", now.Add(49*time.Second))
	g.activity.observe(b, "target.example", now.Add(58*time.Second))
	check("traffic promoted omitted IP", b, 443, true, uint8(consts.OutboundDirect), 37)
	check("complete IP eviction", a, 443, false, 0, 0)
	if !g.Verify(domain, a).Paired {
		t.Fatal("capacity eviction destroyed verification evidence")
	}
	g.Sweep(now.Add(68 * time.Second))
	check("GC restored kernel direct", b, 443, false, 0, 0)
	if g.Verify(domain, b).Paired {
		t.Fatal("expired verification evidence survived GC")
	}
}
