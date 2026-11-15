//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"golang.org/x/sys/unix"
)

func lookupHandoff(m *ebpf.Map, key any, result *bpftestRoutingResult) error {
	var handoff bpftestRoutingHandoff
	err := m.Lookup(key, &handoff)
	*result = handoff.Result
	return err
}

func assertDirectTCPFlow(t *testing.T, obj *bpftestObjects, key bpftestTuplesKey, mark uint32) {
	t.Helper()
	var handoff bpftestRoutingHandoff
	if err := obj.RoutingTuplesMap.Lookup(key, &handoff); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("kernel-direct TCP created handoff: %+v, %v", handoff, err)
	}
	var flow bpftestTcpFlowState
	err := obj.TcpFlowMap.Lookup(key, &flow)
	if err != nil || flow.Fallback != 0 || flow.Mark != mark {
		t.Fatalf("direct flow lost mark: %+v, %v; want %d", flow, err, mark)
	}
}

func TestHandoffSourceOrigin(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	installRoutingFlow(t, obj, []bpftestMatchSet{
		{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionCapture), Flags: 2 << 3},
		{Type: uint8(consts.MatchType_Fallback)},
	})
	sport := uint16(41000)
	for _, ipv6 := range []bool{false, true} {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			for _, tc := range []struct {
				name    string
				entry   *ebpf.Program
				origin  plugin.SourceOrigin
				ingress bool
			}{
				{"LAN L2", obj.LanIngressL2, plugin.SourceLAN, true},
				{"LAN L3", obj.TestLanIngressL3, plugin.SourceLAN, true},
				{"local", obj.TproxyWanEgressL2, plugin.SourceLocal, false},
				{"forwarded WAN", obj.TproxyWanEgressL2, plugin.SourceUnknown, true},
			} {
				t.Run(fmt.Sprintf("%s/ipv6=%v/proto=%d", tc.name, ipv6, proto), func(t *testing.T) {
					sport++
					source, destination := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.2"), sport), netip.MustParseAddrPort("198.51.100.1:443")
					if ipv6 {
						source, destination = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::2"), sport), netip.MustParseAddrPort("[2001:db8::1]:443")
					}
					packet := bridgePacket(source, destination, proto, net.HardwareAddr{2, 0, 0, 0, 0, 1}, 2)
					ctx := make([]byte, 256)
					binary.NativeEndian.PutUint32(ctx[40:44], uint32(loopback.Index))
					if tc.ingress {
						binary.NativeEndian.PutUint32(ctx[36:40], uint32(loopback.Index))
					}
					status, _, _, err := runBpfProgram(tc.entry, packet, ctx)
					if err != nil {
						t.Fatal(err)
					}
					key := bpftestTuplesKey{Sport: nativeUint16(sport), Dport: nativeUint16(443), L4proto: proto}
					key.Sip.U6Addr8, key.Dip.U6Addr8 = source.Addr().As16(), destination.Addr().As16()
					var handoff bpftestRoutingHandoff
					err = obj.RoutingTuplesMap.Lookup(key, &handoff)
					if tc.origin == plugin.SourceUnknown {
						if status != ^uint32(0) || !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("forwarded traffic became local: status=%d handoff=%+v err=%v", status, handoff, err)
						}
						return
					}
					if err != nil || status != 7 || handoff.Result.SourceOrigin != uint8(tc.origin) {
						t.Fatalf("source lost: status=%d handoff=%+v err=%v", status, handoff, err)
					}
					if tc.name == "LAN L3" && handoff.Result.Mac != [6]byte{} {
						t.Fatalf("L3 source gained a MAC: %+v", handoff.Result)
					}
				})
			}
		}
	}
}

// Userspace re-evaluates pname() rules, so the handoff carries the local
// process name the kernel matched.
func TestHandoffCarriesLocalProcessName(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	process := bpftestMatchSet{Type: uint8(consts.MatchType_ProcessName), Action: uint8(consts.MatchActionRoute), Outbound: 2}
	copy(process.Value[:], "curl")
	installRoutingFlow(t, obj, []bpftestMatchSet{process, {Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)}})
	query := bpftestOutboundConnectivityQuery{Outbound: 2, Ipversion: 4, L4proto: unix.IPPROTO_TCP}
	if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	if status, _, _, err := runBpfProgram(obj.TestEntryPname, packet, ctx); err != nil || status != 7 {
		t.Fatalf("local process flow: status %d, error %v; want redirect", status, err)
	}
	var handoff bpftestRoutingHandoff
	if err := obj.RoutingTuplesMap.Lookup(key, &handoff); err != nil {
		t.Fatal(err)
	}
	if handoff.Result.Outbound != 2 || handoff.Result.SourceOrigin != uint8(plugin.SourceLocal) || string(bytes.TrimRight(handoff.Pname[:], "\x00")) != "curl" {
		t.Fatalf("handoff = %+v, want outbound 2 from curl", handoff)
	}
}
