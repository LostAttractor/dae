// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
)

func TestMITMGeodataReloadKernelCapture(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", dir)
	host, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "fixture", Plugin: &controlTestPlugin{plan: pluginGeodataPlan("destinations")}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for generation, data := range []struct{ subnet, domain string }{
		{"198.51.100.0/24", "old.example"},
		{"198.51.100.0/24", "new.example"},
		{"203.0.113.0/24", "new.example"},
	} {
		writePluginGeodata(t, dir, data.subnet, data.domain, "unused.example")
		next, err := host.PrepareSuccessor()
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := PrepareMITM(t.Context(), next, []string{dir})
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Host.Close()
		rules := prepareFlowRulesForTest(t, "dport(443) -> must", "dport(443) -> direct(mark:37)")
		rules.destinations = prepared.plan.Destinations
		rules.enableMITMPlan(prepared.plan)
		rules.bypassAPI(443, []net.Addr{
			&net.IPNet{IP: net.ParseIP("198.51.100.254"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("203.0.113.254"), Mask: net.CIDRMask(24, 32)},
		})
		matcher, builder := routingMatcherForTest(t, rules)
		builder.bpf = state
		if err := builder.BuildKernspace(); err != nil {
			t.Fatal(err)
		}
		for i, test := range []struct{ name, destination, domain string }{
			{"old target", "198.51.100.1:443", "old.example"},
			{"changed domain", "198.51.100.1:443", "new.example"},
			{"changed subnet", "203.0.113.1:443", "new.example"},
			{"SSH", "10.0.0.1:22", data.domain},
			{"unrelated HTTPS", "198.51.100.1:443", "outside.example"},
			{"unrelated HTTPS new subnet", "203.0.113.1:443", "outside.example"},
			{"missing DNS", "198.51.100.1:443", ""},
			{"missing DNS new subnet", "203.0.113.1:443", ""},
			{"wrong port", "198.51.100.1:8443", data.domain},
			{"wrong port new subnet", "203.0.113.1:8443", data.domain},
			{"API bypass", "198.51.100.254:443", data.domain},
			{"API bypass", "203.0.113.254:443", data.domain},
		} {
			dst := netip.MustParseAddrPort(test.destination)
			var domains bpfDomainRouting
			if test.domain != "" {
				bitmap := matcher.domainMatcher.MatchDomainBitmap(test.domain)
				copy(domains.Routing[:], bitmap)
				copy(domains.Bump[:], bitmap)
			}
			if err := collection.Maps["domain_routing_map"].Update(dst.Addr().As16(), domains, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				// Fresh tuples avoid established TCP and cached UDP from previous inputs.
				src := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(47000+generation*100+i))
				packet, ipProto := routingKernelPacket(src, dst, proto)
				key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: ipProto}
				key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
				capture := netip.MustParsePrefix(data.subnet).Contains(dst.Addr()) && test.domain == data.domain && dst.Port() == 443
				if test.name == "API bypass" && proto == consts.L4ProtoType_TCP {
					capture = false
				}
				want := ^uint32(0) // TCX_NEXT: remain in the kernel, without proxy state.
				if capture {
					want = 7
				}
				for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
					if err != nil || verdict != want {
						t.Fatalf("generation=%d %s %s %v: verdict=%d, err=%v, want=%d", generation, test.name, name, proto, verdict, err, want)
					}
					var result bpfRoutingResult
					err = lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &result)
					if !capture {
						if !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("kernel-direct flow retained proxy state: %+v, %v", result, err)
						}
					} else if err != nil || result.CaptureFlags != captureDestination || result.Outbound != uint8(consts.OutboundControlPlaneRouting) || result.Mark != 0 || result.Must != 0 {
						t.Fatalf("destination capture altered handoff semantics: %+v, %v", result, err)
					}
				}
			}
		}
	}
}
