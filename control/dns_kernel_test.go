// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func lookupKernelHandoff(m *ebpf.Map, key any, result *bpfRoutingResult) error {
	var value bpfRoutingHandoff
	err := m.Lookup(key, &value)
	*result = value.Result
	return err
}

func dnsKernelCollection(t *testing.T) (*ebpf.Collection, *BPFState) {
	return dnsKernelGeneration(t, nil, 0)
}

func dnsKernelGeneration(t *testing.T, shared map[string]*ebpf.Map, generation uint32) (*ebpf.Collection, *BPFState) {
	t.Helper()
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
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: shared})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(collection.Close)
	if err := collection.Variables["routing_generation"].Set(generation); err != nil {
		t.Fatal(err)
	}
	state := &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{
		RoutingMap: collection.Maps["routing_map"], RoutingProfileMap: collection.Maps["routing_profile_map"], RoutingInterfaceMap: collection.Maps["routing_interface_map"], LpmArrayMap: collection.Maps["lpm_array_map"], UnusedLpmType: collection.Maps["unused_lpm_type"],
	}, bpfVariables: bpfVariables{DefaultRoutingProfile: collection.Variables["default_routing_profile"]}}}
	return collection, state
}

func TestDNSRelayKernelCapture(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	prepared := prepareFlowRulesForTest(t, "dip(192.0.2.54) -> must\ndip(192.0.2.56) -> dnat(198.51.100.53)", "dip(192.0.2.55) -> block\ndport(53) -> direct(mark:37)")
	prepared.bypassAPI(53, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	_, builder := routingMatcherForTest(t, prepared)
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	for i, test := range []struct {
		name, destination string
		capture           bool
		flags             uint8
		mark              uint32
		block             bool
	}{
		{"DNS", "192.0.2.53:53", true, 8, 37, false},
		{"IPv6 DNS", "[2001:db8::53]:53", true, 8, 37, false},
		{"must bypass", "192.0.2.54:53", false, 0, 37, false},
		{"explicit block", "192.0.2.55:53", false, 0, 0, true},
		{"DNAT DNS", "192.0.2.56:53", true, captureDestination, 0, false},
		{"API bypass", "10.0.0.1:53", false, 0, 0, false},
		{"SSH", "10.0.0.1:22", false, 0, 0, false},
		{"unrelated HTTPS without DNS", "198.51.100.1:443", false, 0, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				dst := netip.MustParseAddrPort(test.destination)
				srcIP := netip.MustParseAddr("192.0.2.1")
				if dst.Addr().Is6() {
					srcIP = netip.MustParseAddr("2001:db8::1")
				}
				src := netip.AddrPortFrom(srcIP, uint16(46000+i))
				packet, ipProto := routingKernelPacket(src, dst, proto)
				capture, flags, mark := test.capture, test.flags, test.mark
				if test.name == "API bypass" && proto == consts.L4ProtoType_UDP {
					capture, flags, mark = true, 8, 37
				}
				want := ^uint32(0)
				if capture {
					want = 7
				}
				if test.block {
					want = 2
				}
				for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
					if err != nil || verdict != want {
						t.Fatalf("%s proto=%d: verdict=%d want=%d error=%v", name, proto, verdict, want, err)
					}
					if capture {
						key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: ipProto}
						key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
						var result bpfRoutingResult
						err := lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &result)
						outbound := uint8(consts.OutboundDirect)
						if flags == captureDestination {
							outbound = uint8(consts.OutboundControlPlaneRouting)
						}
						if err != nil || result.CaptureFlags != flags || result.Mark != mark || result.Must != 0 || result.Outbound != outbound {
							t.Fatalf("capture changed policy: %+v %v", result, err)
						}
					}
				}
			}
		})
	}
}

func TestDNSKernelMustWithCachedUDPSource(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	_, builder := routingMatcherForTest(t, prepareFlowRulesForTest(t, "dip(192.0.2.53) && dport(53) -> must", "dport(443) -> proxy(mark:11)\ndport(53) -> proxy(mark:37)"))
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["outbound_connectivity_map"].Update(bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: 4, L4proto: 17}, uint32(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
		for j, bound := range []bool{false, true} {
			src := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(45000+2*i+j))
			cacheKey := bpfUdpRoutingCacheKey{Sport: common.Htons(src.Port())}
			cacheKey.Sip.U6Addr8 = src.Addr().As16()
			for _, test := range []struct {
				target  string
				must    uint8
				mark    uint32
				capture uint8
			}{
				{"192.0.2.53:443", 0, 11, 0},
				{"192.0.2.53:53", 1, 11, 0},
				{"192.0.2.54:53", 0, 37, 8},
			} {
				dst := netip.MustParseAddrPort(test.target)
				packet, proto := routingKernelPacket(src, dst, consts.L4ProtoType_UDP)
				verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
				if err != nil || verdict != 7 {
					t.Fatalf("%s bound=%v %s verdict=%d err=%v", name, bound, test.target, verdict, err)
				}
				key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: proto}
				key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
				var result bpfRoutingResult
				if err := lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &result); err != nil {
					t.Fatal(err)
				}
				if result.Must != test.must || result.Mark != test.mark || result.CaptureFlags != test.capture || result.Outbound != uint8(consts.OutboundUserDefinedMin) {
					t.Fatalf("%s bound=%v target=%s result=%+v", name, bound, test.target, result)
				}
				if bound && dst.Port() == 443 {
					if err := collection.Maps["udp_bindings_map"].Update(cacheKey, uint64(0), ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
				}
			}
			var cached bpfUdpRoutingCacheValue
			if err := collection.Maps["udp_routing_cache_map"].Lookup(cacheKey, &cached); err != nil {
				t.Fatal(err)
			}
			if cached.Result.Must != 0 || cached.Result.Mark != 11 || cached.Result.Outbound != uint8(consts.OutboundUserDefinedMin) {
				t.Fatalf("DNS replaced non-DNS source policy: %+v", cached.Result)
			}
		}
	}
}
