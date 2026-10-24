// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func TestAPIAddressRefreshKernelCapture(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	rules := prepareFlowRulesForTest(t, "dip(192.0.2.0/24,'2001:db8::/32') && dport(8081) -> bump", "dport(8081) -> block\ndport(443) -> direct(mark:37)")
	rules.bypassAPI(8081, nil)
	matcher, _ := routingMatcherForTest(t, rules)
	matcher.bpf = state
	if err := matcher.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	if err := collection.Variables["api_port"].Set(common.Htons(8081)); err != nil {
		t.Fatal(err)
	}
	plane := &ControlPlane{core: &controlPlaneCore{bpf: state}, routingMatcher: matcher, routingState: matcher.routingState, kernelReady: true}
	for generation, host := range []string{"192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2"} {
		plane.apiListen = net.JoinHostPort(host, "8081")
		if err := plane.RefreshAPIRouting(t.Context()); err != nil {
			t.Fatal(err)
		}
		if current, err := plane.APIRoutingCurrent(); !current || err != nil {
			t.Fatalf("refreshed API routing is not current: %v, %v", current, err)
		}
		for i, test := range []struct {
			destination string
			api         bool
		}{
			{"192.0.2.1:8081", host == "192.0.2.1"},
			{"192.0.2.2:8081", host == "192.0.2.2"},
			{"192.0.2.3:8081", false},
			{"[2001:db8::1]:8081", host == "2001:db8::1"},
			{"[2001:db8::2]:8081", host == "2001:db8::2"},
			{"10.0.0.1:22", false},
			{"198.51.100.1:443", false},
		} {
			dst := netip.MustParseAddrPort(test.destination)
			var addresses *ebpf.Map
			if err := state.LpmArrayMap.Lookup(*matcher.apiSetSlot, &addresses); err != nil {
				t.Fatal(err)
			}
			var exempt uint32
			err := addresses.Lookup(cidrToBpfLpmKey(netip.PrefixFrom(dst.Addr(), dst.Addr().BitLen())), &exempt)
			addresses.Close()
			if test.api && (err != nil || exempt != 1) || !test.api && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("generation=%d %s exemption=%d err=%v", generation, test.destination, exempt, err)
			}
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				source := netip.MustParseAddr("198.51.100.2")
				if dst.Addr().Is6() {
					source = netip.MustParseAddr("2001:db8:1::2")
				}
				captured := dst.Port() == 8081 && !(test.api && proto == consts.L4ProtoType_TCP)
				want := ^uint32(0)
				if captured {
					want = 7
				}
				for n, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					// LAN and local policy cases must not reuse each other's active UDP source.
					src := netip.AddrPortFrom(source, uint16(48000+generation*100+i+n*1000))
					packet, ipProto := routingKernelPacket(src, dst, proto)
					key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: ipProto}
					key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
					verdict, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
					if err != nil || verdict != want {
						t.Fatalf("generation=%d %s %v %s verdict=%d, want=%d err=%v", generation, test.destination, proto, name, verdict, want, err)
					}
					var result bpfRoutingResult
					err = lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &result)
					if captured {
						if err != nil || result.Outbound != uint8(consts.OutboundControlPlaneRouting) || result.Mark != 0 {
							t.Fatalf("captured flow lost its routing handoff: %+v, %v", result, err)
						}
					} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("kernel-direct flow retained proxy state: %+v, %v", result, err)
					}
				}
			}
		}
	}

	previous := slices.Clone(plane.apiBypass)
	previousTrie := matcher.lpmMatcher[*matcher.apiSetSlot]
	outer := state.LpmArrayMap
	closed, err := outer.Clone()
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	state.LpmArrayMap = closed
	plane.apiListen = "192.0.2.3:8081"
	err = plane.RefreshAPIRouting(t.Context())
	state.LpmArrayMap = outer
	if err == nil || !slices.Equal(previous, plane.apiBypass) || matcher.lpmMatcher[*matcher.apiSetSlot] != previousTrie {
		t.Fatalf("failed kernel publication replaced accepted state: %v", err)
	}
	var retained *ebpf.Map
	if err := outer.Lookup(*matcher.apiSetSlot, &retained); err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	var value uint32
	if err := retained.Lookup(cidrToBpfLpmKey(netip.MustParsePrefix("2001:db8::2/128")), &value); err != nil || value != 1 {
		t.Fatalf("failed publication lost the previous kernel set: %d, %v", value, err)
	}
}
