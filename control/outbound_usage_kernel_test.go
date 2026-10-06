// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func TestOutboundPruningKernelIntegration(t *testing.T) {
	testOutboundPolicyKernelCapture(t, "random")
}

func TestFailoverKernelCapture(t *testing.T) {
	testOutboundPolicyKernelCapture(t, "failover")
}

func testOutboundPolicyKernelCapture(t *testing.T, policy string) {
	t.Helper()
	collection, state := dnsKernelCollection(t)
	conf := outboundUsageConfig(t, `
global {}
node { node: 'socks5://127.0.0.1:1' }
group {
 unused { policy: random }
 proxy { policy: `+policy+` }
}
routing {
 domain(full: target.example) && dport(443) -> proxy(mark:37, skip_while_noalive)
 fallback: direct
 policy { inactive { dport(22) -> unused
                     fallback: unused } }
}`)
	built, err := new(controlPlaneCore).buildOutbounds(t.Context(), outboundUsageNodes(conf), conf.Group, &conf.Routing, &conf.Global, consts.OutboundDirect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeDialerGroups(built.outbounds) })
	if len(built.outbounds) != 3 || built.nameToID["proxy"] != uint8(consts.OutboundUserDefinedMin) {
		t.Fatalf("unexpected compacted outbound IDs: %v", built.nameToID)
	}
	prepared := preparedRules{routing: &conf.Routing, validationOutbounds: built.validationOutbounds}
	prepared.bypassAPI(443, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	builder, err := compileTestRouting(prepared, built.nameToID, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	for round, alive := range []bool{false, true} {
		for i, tc := range []struct{ name, address, domain string }{
			{"SSH", "10.0.0.1:22", ""},
			{"missing DNS", "198.51.100.1:443", ""},
			{"unrelated HTTPS", "198.51.100.2:443", "outside.example"},
			{"target", "198.51.100.3:443", "target.example"},
			{"wrong port", "198.51.100.4:22", "target.example"},
			{"API bypass", "10.0.0.1:443", "target.example"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dst := netip.MustParseAddrPort(tc.address)
				if tc.domain != "" {
					var mapping bpfDomainRouting
					bits := matcher.domainMatcher.MatchDomainBitmap(tc.domain)
					copy(mapping.Routing[:], bits)
					copy(mapping.Bump[:], bits)
					if err := collection.Maps["domain_routing_map"].Update(dst.Addr().As16(), mapping, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
				}
				for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
					src := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(40000+round*100+i))
					packet, ipProto := routingKernelPacket(src, dst, proto)
					connectivityKey := bpfOutboundConnectivityQuery{Outbound: built.nameToID["proxy"], Ipversion: 4, L4proto: ipProto}
					if err := collection.Maps["outbound_connectivity_map"].Update(connectivityKey, encodeOutboundConnectivity(alive, false, consts.OutboundBlock), ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					capture := alive && tc.domain == "target.example" && dst.Port() == 443 && (tc.name != "API bypass" || proto == consts.L4ProtoType_UDP)
					want := ^uint32(0) // TCX_NEXT: direct stays in the kernel.
					if capture {
						want = 7 // TC_ACT_REDIRECT
					}
					for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
						verdict, err := collection.Programs[program].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
						if err != nil || verdict != want {
							t.Fatalf("%s proto=%d alive=%v: verdict=%d, want=%d, err=%v", program, proto, alive, verdict, want, err)
						}
						if capture {
							key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: ipProto}
							key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
							var result bpfRoutingResult
							if err := lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &result); err != nil || result.Outbound != built.nameToID["proxy"] || result.Mark != 37 {
								t.Fatalf("compacted target lost its routing result: %+v, %v", result, err)
							}
						}
					}
				}
			})
		}
	}
}
