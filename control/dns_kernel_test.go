// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
)

func lookupKernelHandoff(m *ebpf.Map, key any, result *bpfRoutingResult) error {
	var value bpfRoutingHandoff
	err := m.Lookup(key, &value)
	*result = value.Result
	return err
}

func lookupKernelPacketHandoff(collection *ebpf.Collection, ctx []byte, key bpfTuplesKey, result *bpfRoutingResult) error {
	if key.L4proto != 17 || key.Dport != common.Htons(53) {
		return lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, result)
	}
	cookie := uint64(binary.NativeEndian.Uint32(ctx[52:56])) | uint64(binary.NativeEndian.Uint32(ctx[56:60]))<<32
	if binary.NativeEndian.Uint32(ctx[48:52]) != routingabi.DNS_METADATA_MARK || cookie == 0 {
		return fmt.Errorf("missing DNS cookie: %x", ctx[48:60])
	}
	var handoff bpfDnsHandoff
	if err := collection.Maps["dns_handoff_map"].Lookup(cookie, &handoff); err != nil {
		return err
	}
	if handoff.Reply.Tuple != key {
		return fmt.Errorf("DNS tuple mismatch: %+v != %+v", handoff.Reply.Tuple, key)
	}
	*result = handoff.Result
	return nil
}

func dnsKernelCollection(t *testing.T) (*ebpf.Collection, *BPFState) {
	return dnsKernelGeneration(t, nil, 0)
}

func dnsKernelGeneration(t *testing.T, shared map[string]*ebpf.Map, generation uint32) (*ebpf.Collection, *BPFState) {
	return routingKernelFixture(t, shared, generation, nil)
}

func routingKernelFixture(t testing.TB, shared map[string]*ebpf.Map, generation uint32, configure func(*ebpf.CollectionSpec)) (*ebpf.Collection, *BPFState) {
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
	if configure != nil {
		configure(spec)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: shared})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(collection.Close)
	allowHTTPClientsForTest(t, collection)
	if err := collection.Variables["routing_generation"].Set(generation); err != nil {
		t.Fatal(err)
	}
	state := &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{
		DomainRoutingMap: collection.Maps["domain_routing_map"], HttpClientsMap: collection.Maps["http_clients_map"], RoutingMap: collection.Maps["routing_map"], RoutingProfileMap: collection.Maps["routing_profile_map"], RoutingInterfaceMap: collection.Maps["routing_interface_map"], LpmArrayMap: collection.Maps["lpm_array_map"],
	}, bpfVariables: bpfVariables{DefaultRoutingProfile: collection.Variables["default_routing_profile"]}}}
	return collection, state
}

func TestDNSRelayKernelCapture(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	prepared := prepareFlowRulesForTest(t, "dip(192.0.2.54) -> must\ndip(192.0.2.56) -> dnat(198.51.100.53)", "dip(192.0.2.55) -> block\ndport(53) -> direct(mark:37)")
	prepared.bypassAPI(53, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	builder, _ := routingMatcherForTest(t, prepared)
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
				for n, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					// Policy cases must not reuse another origin's live UDP source.
					src := netip.AddrPortFrom(src.Addr(), src.Port()+uint16(n)*1000)
					packet, ipProto := routingKernelPacket(src, dst, proto)
					out := make([]byte, 256)
					verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), ContextOut: out, Repeat: 1})
					if err != nil || verdict != want {
						t.Fatalf("%s proto=%d: verdict=%d want=%d error=%v", name, proto, verdict, want, err)
					}
					if capture {
						key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: ipProto}
						key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
						var result bpfRoutingResult
						err := lookupKernelPacketHandoff(collection, out, key, &result)
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
	builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "dip(192.0.2.53) && dport(53) -> must", "dport(443) -> proxy(mark:11)\ndport(53) -> proxy(mark:37)"))
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["outbound_connectivity_map"].Update(bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: 4, L4proto: 17}, bpfOutboundConnectivity{State: outboundConnectivityAlive}, ebpf.UpdateAny); err != nil {
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
				out := make([]byte, 256)
				verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), ContextOut: out, Repeat: 1})
				if err != nil || verdict != 7 {
					t.Fatalf("%s bound=%v %s verdict=%d err=%v", name, bound, test.target, verdict, err)
				}
				key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: proto}
				key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
				var result bpfRoutingResult
				if err := lookupKernelPacketHandoff(collection, out, key, &result); err != nil {
					t.Fatal(err)
				}
				if result.Must != test.must || result.Mark != test.mark || result.CaptureFlags != test.capture || result.Outbound != uint8(consts.OutboundUserDefinedMin) {
					t.Fatalf("%s bound=%v target=%s result=%+v", name, bound, test.target, result)
				}
				if bound && dst.Port() == 443 {
					binding := bpfUdpBinding{RouteEpoch: result.RouteEpoch, Mac: result.Mac, SourceOrigin: result.SourceOrigin}
					if err := collection.Maps["udp_bindings_map"].Update(cacheKey, binding, ebpf.UpdateAny); err != nil {
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

func TestDNSMetadataLRUEviction(t *testing.T) {
	collection, state := routingKernelFixture(t, nil, 1, func(spec *ebpf.CollectionSpec) {
		spec.Maps["dns_handoff_map"].MaxEntries = 1
		spec.Maps["dns_reply_map"].MaxEntries = 1
	})
	builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "dport(53) -> direct"))
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.0.2.1:45000"), netip.MustParseAddrPort("192.0.2.53:53"), consts.L4ProtoType_UDP)
	var first, last uint64
	for i := range 256 {
		out := make([]byte, 256)
		verdict, err := collection.Programs["lan_ingress_l2"].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), ContextOut: out, Repeat: 1})
		if err != nil || verdict != 7 {
			t.Fatalf("capture: verdict=%d err=%v", verdict, err)
		}
		cookie := uint64(binary.NativeEndian.Uint32(out[52:56])) | uint64(binary.NativeEndian.Uint32(out[56:60]))<<32
		if cookie <= last {
			t.Fatalf("cookie reused after eviction: %d <= %d", cookie, last)
		}
		if i == 0 {
			first = cookie
		}
		last = cookie
		var handoff bpfDnsHandoff
		if err := collection.Maps["dns_handoff_map"].Lookup(cookie, &handoff); err != nil {
			t.Fatal(err)
		}
		if err := collection.Maps["dns_reply_map"].Update(cookie, handoff.Reply, ebpf.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
	}
	var handoff bpfDnsHandoff
	var reply bpfDnsReply
	if err := collection.Maps["dns_handoff_map"].Lookup(first, &handoff); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("handoff did not evict old cookie: %v", err)
	}
	if err := collection.Maps["dns_reply_map"].Lookup(first, &reply); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("reply did not evict old cookie: %v", err)
	}
	var counter bpfDnsCookie
	if err := collection.Maps["dns_cookie_map"].Lookup(uint32(0), &counter); err != nil || counter.Value != last {
		t.Fatalf("LRU changed the cookie counter: %+v err=%v", counter, err)
	}
}

// Scope-only fixtures explicitly admit every client; admission fixtures replace
// this private table with their own ordered policy.
func allowHTTPClientsForTest(t testing.TB, collection *ebpf.Collection) {
	t.Helper()
	matcher, err := clientmatch.Parse([]string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	table, err := httpClientMap(matcher.Compile(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()
	if err := collection.Maps["http_clients_map"].Update(uint32(0), table, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}
