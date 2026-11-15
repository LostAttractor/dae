//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"golang.org/x/sys/unix"
)

func dnsTestContext(t *testing.T) []byte {
	t.Helper()
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	ctx := make([]byte, 256)
	binary.NativeEndian.PutUint32(ctx[40:44], uint32(loopback.Index))
	return ctx
}

func TestDNSMustBindingWithoutRouteCache(t *testing.T) {
	for _, test := range []struct {
		name                          string
		bound, incoming               plugin.SourceOrigin
		otherMAC, staleEpoch, allowed bool
	}{
		{"local_to_lan", plugin.SourceLocal, plugin.SourceLAN, false, false, false},
		{"lan_to_local", plugin.SourceLAN, plugin.SourceLocal, false, false, false},
		{"lan_other_mac", plugin.SourceLAN, plugin.SourceLAN, true, false, false},
		{"lan_same_source", plugin.SourceLAN, plugin.SourceLAN, false, false, true},
		{"local_other_mac", plugin.SourceLocal, plugin.SourceLocal, true, false, true},
		{"stale_epoch", plugin.SourceLAN, plugin.SourceLAN, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			obj, err := loadTestObjects(t, "TproxyWanEgressL2", "LanIngressL2")
			if err != nil {
				t.Fatal(err)
			}
			installRoutingFlow(t, obj, []bpftestMatchSet{
				{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMust)},
				{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)},
				{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundControlPlaneRouting)},
			})
			source, dest := netip.MustParseAddrPort("192.0.2.2:52001"), netip.MustParseAddrPort("198.51.100.1:53")
			key := bpftestUdpRoutingCacheKey{Sport: nativeUint16(source.Port())}
			key.Sip.U6Addr8 = source.Addr().As16()
			binding := bpftestUdpBinding{SourceOrigin: uint8(test.bound), Mac: [6]uint8{2, 0, 0, 0, 0, 2}}
			if test.staleEpoch {
				binding.RouteEpoch = 1
			}
			if err := obj.UdpBindingsMap.Update(key, binding, ebpf.UpdateNoExist); err != nil {
				t.Fatal(err)
			}
			packet, ctx := bridgePacket(source, dest, unix.IPPROTO_UDP, nil, 0), dnsTestContext(t)
			if test.otherMAC {
				packet[11]++
			}
			program := obj.TproxyWanEgressL2
			if test.incoming == plugin.SourceLAN {
				program = obj.LanIngressL2
				copy(ctx[36:40], ctx[40:44])
			}
			status, _, _, err := runBpfProgram(program, packet, ctx)
			want := uint32(2)
			if test.allowed {
				want = 7
			}
			if err != nil || status != want {
				t.Fatalf("must: status=%d want=%d err=%v", status, want, err)
			}
			var route bpftestUdpRoutingCacheValue
			err = obj.UdpRoutingCacheMap.Lookup(key, &route)
			if test.allowed {
				var tupleKey bpftestTuplesKey
				var handoff bpftestRoutingHandoff
				if err != nil || !obj.RoutingTuplesMap.Iterate().Next(&tupleKey, &handoff) || handoff.Result.Must != 1 {
					t.Fatalf("valid must lost association/handoff: %+v err=%v", handoff, err)
				}
			} else {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("rejected must wrote route: %+v err=%v", route, err)
				}
				var tupleKey bpftestTuplesKey
				var handoff bpftestRoutingHandoff
				var tuple bpftestRedirectTuple
				var path bpftestRedirectEntry
				if obj.RoutingTuplesMap.Iterate().Next(&tupleKey, &handoff) || obj.RedirectTrack.Iterate().Next(&tuple, &path) {
					t.Fatal("rejected must changed handoff or return ownership")
				}
			}
		})
	}
}
