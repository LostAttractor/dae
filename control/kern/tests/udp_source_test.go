//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"golang.org/x/sys/unix"
)

func TestUDPConcurrentFirstPacketsKeepSource(t *testing.T) {
	for _, test := range []struct {
		name        string
		first, next plugin.SourceOrigin
		changeMAC   bool
		allowed     bool
	}{
		{"local_to_lan", plugin.SourceLocal, plugin.SourceLAN, false, false},
		{"lan_to_local", plugin.SourceLAN, plugin.SourceLocal, false, false},
		{"lan_other_mac", plugin.SourceLAN, plugin.SourceLAN, true, false},
		{"lan_same_source", plugin.SourceLAN, plugin.SourceLAN, false, true},
		{"local_other_mac", plugin.SourceLocal, plugin.SourceLocal, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			obj, err := loadTestObjects(t, "TestSaveUdpRoute")
			if err != nil {
				t.Fatal(err)
			}
			run := func(origin plugin.SourceOrigin, mac, outbound uint8) uint32 {
				t.Helper()
				ctx := make([]byte, 256)
				binary.NativeEndian.PutUint32(ctx[8:12], uint32(origin)|uint32(mac)<<8|uint32(outbound)<<16)
				status, _, _, err := runBpfProgram(obj.TestSaveUdpRoute, make([]byte, 64), ctx)
				if err != nil {
					t.Fatal(err)
				}
				return status
			}
			if status := run(test.first, 1, uint8(consts.OutboundDirect)); status != 0 {
				t.Fatalf("first decision: status=%d", status)
			}
			key := bpftestUdpRoutingCacheKey{Sport: nativeUint16(52001)}
			var first bpftestUdpRoutingCacheValue
			if err := obj.UdpRoutingCacheMap.Lookup(key, &first); err != nil {
				t.Fatal(err)
			}
			mac, want := uint8(1), uint32(2)
			if test.changeMAC {
				mac++
			}
			if test.allowed {
				want = 0
			}
			if status := run(test.next, mac, uint8(consts.OutboundBlock)); status != want {
				t.Fatalf("competing decision: status=%d, want %d", status, want)
			}
			var winner bpftestUdpRoutingCacheValue
			if err := obj.UdpRoutingCacheMap.Lookup(key, &winner); err != nil {
				t.Fatal(err)
			}
			if winner.Result != first.Result || !test.allowed && winner.CachedUntil != first.CachedUntil {
				t.Fatalf("competing source changed the winner: %+v", winner)
			}
		})
	}
}

func TestUDPFragmentSourceOwnership(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, test := range []struct {
			name        string
			first, next plugin.SourceOrigin
			changeMAC   bool
			allowed     bool
		}{
			{"local_to_lan", plugin.SourceLocal, plugin.SourceLAN, false, false},
			{"lan_to_local", plugin.SourceLAN, plugin.SourceLocal, false, false},
			{"lan_other_mac", plugin.SourceLAN, plugin.SourceLAN, true, false},
			{"lan_same_source", plugin.SourceLAN, plugin.SourceLAN, false, true},
			{"local_other_mac", plugin.SourceLocal, plugin.SourceLocal, true, true},
		} {
			t.Run(fmt.Sprintf("IPv6=%t/%s", ipv6, test.name), func(t *testing.T) {
				generator := "TestpktgenIpv4FirstUdpFragmentDirect"
				if ipv6 {
					generator = "TestpktgenIpv6FirstUdpFragmentDirect"
				}
				obj, err := loadTestObjects(t, "TproxyWanEgressL2", "LanIngressL2", generator)
				if err != nil {
					t.Fatal(err)
				}
				pktgen := obj.TestpktgenIpv4FirstUdpFragmentDirect
				if ipv6 {
					pktgen = obj.TestpktgenIpv6FirstUdpFragmentDirect
				}
				status, fragment, ctx, err := runBpfProgram(pktgen, make([]byte, 4096-256-320), make([]byte, 256))
				if err != nil || status != 0 {
					t.Fatalf("generate packet: status=%d err=%v", status, err)
				}
				loopback, err := net.InterfaceByName("lo")
				if err != nil {
					t.Fatal(err)
				}
				binary.NativeEndian.PutUint32(ctx[40:44], uint32(loopback.Index))
				installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback)}})
				run := func(origin plugin.SourceOrigin, packet []byte) uint32 {
					t.Helper()
					entry := obj.TproxyWanEgressL2
					binary.NativeEndian.PutUint32(ctx[36:40], 0)
					if origin == plugin.SourceLAN {
						entry = obj.LanIngressL2
						binary.NativeEndian.PutUint32(ctx[36:40], uint32(loopback.Index))
					}
					status, _, _, err := runBpfProgram(entry, packet, ctx)
					if err != nil {
						t.Fatal(err)
					}
					return status
				}
				whole := append([]byte(nil), fragment...)
				if ipv6 {
					binary.BigEndian.PutUint16(whole[56:58], 0)
				} else {
					binary.BigEndian.PutUint16(whole[20:22], 0)
				}
				if status := run(test.first, whole); status != ^uint32(0) {
					t.Fatalf("first packet: status=%d", status)
				}
				var key bpftestUdpRoutingCacheKey
				var first bpftestUdpRoutingCacheValue
				iter := obj.UdpRoutingCacheMap.Iterate()
				if !iter.Next(&key, &first) {
					t.Fatalf("missing first route: %v", iter.Err())
				}
				if test.changeMAC {
					fragment[11]++
				}
				want := uint32(2)
				if test.allowed {
					want = ^uint32(0)
				}
				if status := run(test.next, fragment); status != want {
					t.Fatalf("first fragment: status=%d, want %d", status, want)
				}
				var after bpftestUdpRoutingCacheValue
				if err := obj.UdpRoutingCacheMap.Lookup(key, &after); err != nil {
					t.Fatal(err)
				}
				if after.Result != first.Result || !test.allowed && after.CachedUntil != first.CachedUntil {
					t.Fatal("fragment changed or refreshed another source's route")
				}
			})
		}
	}
}

func TestUDPSourceOwnership(t *testing.T) {
	for _, bound := range []bool{false, true} {
		for _, test := range []struct {
			name        string
			first, next plugin.SourceOrigin
			changeMAC   bool
			unknown     bool
			allowed     bool
		}{
			{"local_to_lan", plugin.SourceLocal, plugin.SourceLAN, false, false, false},
			{"lan_to_local", plugin.SourceLAN, plugin.SourceLocal, false, false, false},
			{"lan_other_mac", plugin.SourceLAN, plugin.SourceLAN, true, false, false},
			{"lan_same_source", plugin.SourceLAN, plugin.SourceLAN, false, false, true},
			{"local_same_source", plugin.SourceLocal, plugin.SourceLocal, false, false, true},
			{"local_other_mac", plugin.SourceLocal, plugin.SourceLocal, true, false, true},
			{"unknown_to_local", plugin.SourceLocal, plugin.SourceLocal, false, true, false},
			{"unknown_to_lan", plugin.SourceLAN, plugin.SourceLAN, false, true, false},
		} {
			t.Run(fmt.Sprintf("bound=%t/%s", bound, test.name), func(t *testing.T) {
				obj, err := loadTestObjects(t, "TproxyWanEgressL2", "LanIngressL2")
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
				source := netip.MustParseAddrPort("192.0.2.2:52001")
				destination := netip.MustParseAddrPort("198.51.100.1:443")
				mac := [6]byte{2, 0, 0, 0, 0, 1}
				ctx := make([]byte, 256)
				binary.NativeEndian.PutUint32(ctx[40:44], uint32(loopback.Index))
				run := func(origin plugin.SourceOrigin, mac [6]byte) uint32 {
					t.Helper()
					entry := obj.TproxyWanEgressL2
					binary.NativeEndian.PutUint32(ctx[36:40], 0)
					if origin == plugin.SourceLAN {
						entry = obj.LanIngressL2
						binary.NativeEndian.PutUint32(ctx[36:40], uint32(loopback.Index))
					}
					packet := bridgePacket(source, destination, unix.IPPROTO_UDP, nil, 2)
					copy(packet[6:12], mac[:])
					status, _, _, err := runBpfProgram(entry, packet, ctx)
					if err != nil {
						t.Fatal(err)
					}
					return status
				}
				if status := run(test.first, mac); status != 7 {
					t.Fatalf("first packet: status=%d", status)
				}
				key := bpftestUdpRoutingCacheKey{Sport: nativeUint16(source.Port())}
				key.Sip.U6Addr8 = source.Addr().As16()
				var before bpftestUdpRoutingCacheValue
				if err := obj.UdpRoutingCacheMap.Lookup(key, &before); err != nil {
					t.Fatal(err)
				}
				if before.Result.SourceOrigin != uint8(test.first) || before.Result.Mac != mac {
					t.Fatalf("incorrect first source: %+v", before.Result)
				}
				if test.unknown {
					before.Result.SourceOrigin = uint8(plugin.SourceUnknown)
					if err := obj.UdpRoutingCacheMap.Update(key, before, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
				}
				if bound {
					binding := bpftestUdpBinding{RouteEpoch: before.Result.RouteEpoch, Mac: before.Result.Mac, SourceOrigin: before.Result.SourceOrigin}
					if err := obj.UdpBindingsMap.Update(key, binding, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					// The binding lifetime does not depend on the initial routing-cache entry.
					if err := obj.UdpRoutingCacheMap.Delete(key); err != nil {
						t.Fatal(err)
					}
				}
				if test.changeMAC {
					mac[5]++
				}
				want := uint32(2)
				if test.allowed {
					want = 7
				}
				if status := run(test.next, mac); status != want {
					t.Fatalf("later packet: status=%d, want %d", status, want)
				}
				if !bound && !test.allowed {
					var after bpftestUdpRoutingCacheValue
					if err := obj.UdpRoutingCacheMap.Lookup(key, &after); err != nil {
						t.Fatal(err)
					}
					if after.Result != before.Result || after.CachedUntil != before.CachedUntil {
						t.Fatal("rejected source changed or refreshed the existing route")
					}
				}
				if !test.allowed {
					if bound {
						if err := obj.UdpBindingsMap.Delete(key); err != nil {
							t.Fatal(err)
						}
					} else {
						before.CachedUntil = 1
						if err := obj.UdpRoutingCacheMap.Update(key, before, ebpf.UpdateAny); err != nil {
							t.Fatal(err)
						}
					}
					if status := run(test.next, mac); status != 7 {
						t.Fatalf("released source: status=%d", status)
					}
					var fresh bpftestUdpRoutingCacheValue
					if err := obj.UdpRoutingCacheMap.Lookup(key, &fresh); err != nil {
						t.Fatal(err)
					}
					if fresh.Result.SourceOrigin != uint8(test.next) || fresh.Result.Mac != mac {
						t.Fatalf("new lifetime kept the old identity: %+v", fresh.Result)
					}
				}
			})
		}
	}
}
