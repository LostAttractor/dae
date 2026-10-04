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
)

func TestConditionalUseKernelIntegration(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	prepared := prepareFlowRulesForTest(t, `domain(full: target.example) && dport(443) -> must`, `
 rule_set {
  ports { dport(443) -> proxy(mark:37) }
  domains { domain(full: target.example, full: mitm.example) -> use(ports) }
 }
 sip(192.0.2.0/24, '2001:db8:1::/64') -> use(domains)`)
	prepared.enableMITMPlan(mitmRoutingPlugin("mitm.example").Plan())
	prepared.bypassAPI(443, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	m, b := routingMatcherForTest(t, prepared)
	b.bpf = state
	if err := b.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	for i, test := range []struct {
		name, source, destination, domain string
		proxy, http, must                 bool
	}{
		{"SSH", "192.0.2.1", "10.0.0.1:22", "target.example", false, false, false},
		{"unrelated HTTPS", "192.0.2.1", "198.51.100.1:443", "outside.example", false, false, false},
		{"missing DNS", "192.0.2.1", "198.51.100.2:443", "", false, false, false},
		{"target", "192.0.2.1", "198.51.100.3:443", "target.example", true, false, true},
		{"wrong source", "203.0.113.1", "198.51.100.4:443", "target.example", false, false, true},
		{"inner predicate miss", "192.0.2.1", "198.51.100.5:8443", "target.example", false, false, false},
		{"MITM preserves proxy route", "192.0.2.1", "198.51.100.6:443", "mitm.example", true, true, false},
		{"MITM preserves direct route", "203.0.113.1", "198.51.100.7:443", "mitm.example", false, true, false},
		{"MITM wrong port", "192.0.2.1", "198.51.100.8:8443", "mitm.example", false, false, false},
		{"API bypass", "192.0.2.1", "10.0.0.1:443", "target.example", true, false, true},
		{"IPv6 target", "2001:db8:1::1", "[2001:db8:2::1]:443", "target.example", true, false, true},
		{"IPv6 missing DNS", "2001:db8:1::1", "[2001:db8:2::2]:443", "", false, false, false},
		{"IPv6 wrong source", "2001:db8:3::1", "[2001:db8:2::3]:443", "target.example", false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dst := netip.MustParseAddrPort(test.destination)
			var mapping bpfDomainRouting
			if test.domain != "" {
				bits := m.domainMatcher.MatchDomainBitmap(test.domain)
				copy(mapping.Routing[:], bits)
				copy(mapping.Bump[:], bits)
			}
			if err := collection.Maps["domain_routing_map"].Update(dst.Addr().As16(), mapping, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				src := netip.AddrPortFrom(netip.MustParseAddr(test.source), uint16(43000+i))
				packet, ipProto := routingKernelPacket(src, dst, proto)
				version := uint8(4)
				if dst.Addr().Is6() {
					version = 6
				}
				connectivity := bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: version, L4proto: ipProto}
				if err := collection.Maps["outbound_connectivity_map"].Update(connectivity, encodeOutboundConnectivity(true, false, consts.OutboundBlock), ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: ipProto}
				key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
				proxy, http, must := test.proxy, test.http, test.must
				if test.name == "API bypass" && proto == consts.L4ProtoType_TCP {
					proxy, http, must = false, false, false
				}
				for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					want := ^uint32(0) // TCX_NEXT: kernel direct.
					if proxy || http {
						want = 7 // TC_ACT_REDIRECT.
					}
					verdict, err := collection.Programs[program].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
					if err != nil || verdict != want {
						t.Fatalf("%s proto=%d: verdict=%d err=%v, want=%d", program, proto, verdict, err, want)
					}
					var result bpfRoutingResult
					err = lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &result)
					if !proxy && !http {
						if !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("kernel direct retained proxy state: %+v, %v", result, err)
						}
						continue
					}
					outbound, mark := uint8(consts.OutboundDirect), uint32(0)
					if proxy {
						outbound, mark = uint8(consts.OutboundUserDefinedMin), 37
					}
					var flags uint8
					if http {
						flags = captureHTTP
					}
					if err != nil || result.Outbound != outbound || result.Mark != mark || (result.Must != 0) != must || result.CaptureFlags != flags {
						t.Fatalf("%s proto=%d: route=%+v err=%v, want outbound=%d mark=%d must=%v capture=%d", program, proto, result, err, outbound, mark, must, flags)
					}
				}
			}
		})
	}
}
