//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func TestFlowControlsDNSAndCapture(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []struct {
		name   string
		pktgen *ebpf.Program
		proto  uint8
	}{
		{"tcp", obj.TestpktgenMacMatch, 6},
		{"udp", obj.TestpktgenUdpRouteCacheMiss, 17},
	} {
		t.Run(network.name, func(t *testing.T) {
			status, packet, ctx, err := runBpfProgram(network.pktgen, make([]byte, 4096-256-320), make([]byte, 256))
			if err != nil || status != 0 {
				t.Fatalf("generate packet: status=%d err=%v", status, err)
			}
			for _, test := range []struct {
				name                string
				port                uint16
				must, bump, capture bool
			}{
				{"SSH unrelated", 22, true, true, true},
				{"HTTPS unrelated", 8443, true, true, true},
				{"normal DNS", 53, false, false, false},
				{"must skips DNS interception", 53, true, false, false},
				{"must does not capture", 443, true, false, false},
				{"bump", 443, false, true, false},
				{"must survives bump", 443, true, true, false},
				{"capture survives bump", 443, true, true, true},
				{"DNS DNAT survives bump", 53, false, true, true},
				{"must does not cancel DNAT", 53, true, false, true},
			} {
				t.Run(test.name, func(t *testing.T) {
					binary.BigEndian.PutUint16(packet[36:38], test.port)
					portRule := func(port uint16, action consts.MatchAction, flags uint8) bpftestMatchSet {
						rule := bpftestMatchSet{Type: uint8(consts.MatchType_Port), Action: uint8(action), Flags: (flags) << 3}
						binary.NativeEndian.PutUint16(rule.Value[:2], port)
						binary.NativeEndian.PutUint16(rule.Value[2:4], port)
						return rule
					}
					var rules []bpftestMatchSet
					// Destination capture precedes controls, which use the final target in userspace.
					if test.capture {
						for _, port := range []uint16{53, 443} {
							rules = append(rules, portRule(port, consts.MatchActionCapture, 2))
						}
					}
					if test.must {
						for _, port := range []uint16{53, 443} {
							rules = append(rules, portRule(port, consts.MatchActionMust, 0))
						}
					}
					if test.bump {
						for _, port := range []uint16{53, 443} {
							rules = append(rules, portRule(port, consts.MatchActionBump, 0))
						}
					}
					rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)})
					rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect)})
					for i, rule := range rules {
						if err := obj.RoutingMap.Update(uint32(i), rule, ebpf.UpdateAny); err != nil {
							t.Fatal(err)
						}
					}
					key := bpftestTuplesKey{Sport: binary.NativeEndian.Uint16(packet[34:36]), Dport: nativeUint16(test.port), L4proto: network.proto}
					key.Sip.U6Addr8 = netip.AddrFrom4([4]byte(packet[26:30])).As16()
					key.Dip.U6Addr8 = netip.AddrFrom4([4]byte(packet[30:34])).As16()
					matched := test.port == 53 || test.port == 443
					redirect := matched && (test.bump || test.capture || test.port == 53 && !test.must)
					for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
						if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
							t.Fatal(err)
						}
						if err := obj.RoutingTuplesMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatal(err)
						}
						want := ^uint32(0) // TCX_NEXT: actual kernel direct.
						if redirect {
							want = 7 // TC_ACT_REDIRECT
						}
						status, _, _, err := runBpfProgram(program, packet, ctx)
						if err != nil || status != want {
							t.Fatalf("%s: status=%d err=%v, want=%d", program, status, err, want)
						}
						var result bpftestRoutingResult
						err = lookupHandoff(obj.RoutingTuplesMap, key, &result)
						if !redirect {
							if !errors.Is(err, ebpf.ErrKeyNotExist) {
								t.Fatalf("kernel direct retained proxy state: %+v, %v", result, err)
							}
							continue
						}
						var must, capture uint8
						if test.must && !test.capture {
							must = 1
						}
						if test.capture {
							capture = 2
						} else if test.port == 53 && !test.must && !test.bump {
							capture = 8
						}
						if err != nil || result.Must != must || result.CaptureFlags != capture {
							t.Fatalf("lost controls: %+v, %v", result, err)
						}
						if network.proto == 17 && program == obj.LanIngressL2 {
							source := bpftestUdpRoutingCacheKey{Sport: key.Sport}
							source.Sip = key.Sip
							var cached bpftestUdpRoutingCacheValue
							err := obj.UdpRoutingCacheMap.Lookup(source, &cached)
							if test.port == 53 && result.Must == 0 {
								if !errors.Is(err, ebpf.ErrKeyNotExist) {
									t.Fatalf("intercepted DNS retained a UDP route: %+v, %v", cached, err)
								}
							} else if err != nil || cached.Result.Outbound != result.Outbound ||
								cached.Result.Mark != result.Mark || cached.Result.Must != result.Must ||
								cached.Result.CaptureFlags != result.CaptureFlags || cached.Result.ProfileId != result.ProfileId ||
								cached.Result.Ifindex != result.Ifindex || cached.Result.Mac != result.Mac ||
								cached.Result.Dscp != result.Dscp || cached.Result.Protocol != result.Protocol ||
								cached.Result.NoSniff != result.NoSniff || cached.Result.RouteEpoch != result.RouteEpoch {
								t.Fatalf("first UDP route was not pinned: %+v, %v", cached, err)
							}
						}
						if (test.bump || test.capture) && result.Outbound != uint8(consts.OutboundControlPlaneRouting) {
							t.Fatalf("capture/bump did not defer routing: %+v", result)
						}
					}
				})
			}
		})
	}
}
