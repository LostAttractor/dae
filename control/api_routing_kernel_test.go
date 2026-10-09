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

func TestAPIAddressReloadKernelCapture(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	state.RouteExemptMap = collection.Maps["route_exempt_map"]
	for generation, host := range []string{"192.0.2.1", "192.0.2.2"} {
		// API bypass must precede explicit capture as well as ordinary routing.
		rules := prepareFlowRulesForTest(t, "dip(192.0.2.0/24) && dport(8081) -> bump", "dport(8081) -> block\ndport(443) -> direct(mark:37)")
		rules.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP(host), Mask: net.CIDRMask(24, 32)}})
		_, builder := routingMatcherForTest(t, rules)
		builder.bpf = state
		if err := builder.BuildKernspace(); err != nil {
			t.Fatal(err)
		}
		plane := &ControlPlane{core: &controlPlaneCore{bpf: state}, apiBypass: rules.apiBypass}
		if err := plane.updateRouteExemptions(); err != nil {
			t.Fatal(err)
		}
		for i, test := range []struct {
			destination string
			api         bool
		}{
			{"192.0.2.1:8081", host == "192.0.2.1"},
			{"192.0.2.2:8081", host == "192.0.2.2"},
			{"192.0.2.3:8081", false},
			{"10.0.0.1:22", false},
			{"198.51.100.1:443", false},
		} {
			dst := netip.MustParseAddrPort(test.destination)
			var exempt uint8
			exemptKey := bpfIpPort{Port: common.Htons(dst.Port())}
			exemptKey.Ip.U6Addr8 = dst.Addr().As16()
			err := state.RouteExemptMap.Lookup(exemptKey, &exempt)
			if test.api && (err != nil || exempt != 1) || !test.api && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("generation=%d %s exemption=%d err=%v", generation, test.destination, exempt, err)
			}
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				src := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.2"), uint16(48000+generation*100+i))
				packet, ipProto := routingKernelPacket(src, dst, proto)
				key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: ipProto}
				key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
				captured := dst.Port() == 8081 && !(test.api && proto == consts.L4ProtoType_TCP)
				want := ^uint32(0)
				if captured {
					want = 7
				}
				for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
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
}
