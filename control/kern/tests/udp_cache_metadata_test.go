//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func TestUDPRoutingCachePreservesSourceMetadata(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	status, packet, ctx, err := runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil || status != 0 {
		t.Fatalf("generate packet: status=%d err=%v", status, err)
	}
	const (
		profileID = uint32(70001)
		directID  = uint32(70002)
		mark      = uint32(0xaabbccdd)
		dscp      = uint8(46)
	)
	mac := [6]byte{2, 0, 0, 0, 0, 37}
	copy(packet[6:12], mac[:])
	packet[15] = dscp << 2
	// Supply an existing interface to BPF_PROG_TEST_RUN without attaching any
	// program to it. A nonzero index detects omitted cache-hit metadata copies.
	ifindex := uint32(loopback.Index)
	binary.NativeEndian.PutUint32(ctx[40:44], ifindex)
	key := bpftestTuplesKey{
		Sport:   binary.NativeEndian.Uint16(packet[34:36]),
		Dport:   binary.NativeEndian.Uint16(packet[36:38]),
		L4proto: unix.IPPROTO_UDP,
	}
	key.Sip.U6Addr8 = netip.AddrFrom4([4]byte(packet[26:30])).As16()
	key.Dip.U6Addr8 = netip.AddrFrom4([4]byte(packet[30:34])).As16()
	profile := bpftestRoutingProfile{Length: 4}
	copy(profile.Steps[:], []uint16{0, 1, 2, 3})
	if err := obj.RoutingProfileMap.Update(profileID, profile, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	direct := bpftestRoutingProfile{Length: 1}
	direct.Steps[0] = 4
	if err := obj.RoutingProfileMap.Update(directID, direct, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := obj.RoutingMap.Update(uint32(4), bpftestMatchSet{Type: uint8(consts.MatchType_Fallback)}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	deleteHandoff := func(t *testing.T) {
		t.Helper()
		if err := obj.RoutingTuplesMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
	}
	portRule := func(action consts.MatchAction, capture uint8) bpftestMatchSet {
		rule := bpftestMatchSet{Type: uint8(consts.MatchType_Port), Action: uint8(action), Flags: capture << 3}
		binary.NativeEndian.PutUint16(rule.Value[:2], 443)
		binary.NativeEndian.PutUint16(rule.Value[2:4], 443)
		return rule
	}
	for _, network := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"LAN", obj.LanIngressL2},
		{"WAN", obj.TproxyWanEgressL2},
	} {
		t.Run(network.name, func(t *testing.T) {
			for _, test := range []struct {
				name     string
				outbound uint8
				capture  uint8
			}{
				{"captured direct", uint8(consts.OutboundDirect), 2},
				{"captured proxy", 2, 2},
				{"proxy", 2, 0},
			} {
				t.Run(test.name, func(t *testing.T) {
					wantOutbound, wantMark, wantMust := test.outbound, mark, uint8(1)
					if test.capture != 0 {
						wantOutbound, wantMark, wantMust = uint8(consts.OutboundControlPlaneRouting), 0, 0
					}
					if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
						t.Fatal(err)
					}
					deleteHandoff(t)
					if err := obj.RoutingProfileMap.Update(profileID, profile, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					if err := obj.RoutingInterfaceMap.Update(ifindex, profileID, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					for index, rule := range []bpftestMatchSet{
						portRule(consts.MatchActionCapture, test.capture),
						portRule(consts.MatchActionMust, 0),
						{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)},
						{Type: uint8(consts.MatchType_Fallback), Outbound: test.outbound, Mark: mark},
					} {
						if err := obj.RoutingMap.Update(uint32(index), rule, ebpf.UpdateAny); err != nil {
							t.Fatal(err)
						}
					}
					connectivity := bpftestOutboundConnectivityQuery{Outbound: test.outbound, L4proto: unix.IPPROTO_UDP, Ipversion: 4}
					if err := obj.OutboundConnectivityMap.Update(connectivity, uint32(0), ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					checkHandoff := func(t *testing.T) {
						t.Helper()
						var result bpftestRoutingResult
						if err := obj.RoutingTuplesMap.Lookup(key, &result); err != nil {
							t.Fatal(err)
						}
						if result.Outbound != wantOutbound || result.Mark != wantMark || result.Must != wantMust || result.CaptureFlags != test.capture {
							t.Fatalf("lost cached routing decision: %+v", result)
						}
						if result.Ifindex != ifindex || result.ProfileId != profileID || result.Mac != mac || result.Dscp != dscp || result.Protocol != 2 || result.RouteEpoch != 0 || result.NoSniff != 0 || result.Pid != 0 || result.Pname != ([16]byte{}) {
							t.Fatalf("lost initial source metadata: %+v", result)
						}
					}
					status, _, _, err := runBpfProgram(network.prog, packet, ctx)
					if err != nil || status != 7 { // TC_ACT_REDIRECT
						t.Fatalf("cache miss: status=%d err=%v", status, err)
					}
					checkHandoff(t)
					var cacheKey bpftestUdpRoutingCacheKey
					var cached bpftestUdpRoutingCacheValue
					iter := obj.UdpRoutingCacheMap.Iterate()
					if !iter.Next(&cacheKey, &cached) {
						t.Fatalf("missing routing cache: %v", iter.Err())
					}
					if cached.CachedUntil == 0 || cached.Result.Outbound != wantOutbound || cached.Result.Mark != wantMark || cached.Result.Must != wantMust || cached.Result.CaptureFlags != test.capture {
						t.Fatalf("incomplete cached decision: %+v", cached)
					}
					cached.CachedUntil = math.MaxUint64
					if err := obj.UdpRoutingCacheMap.Update(cacheKey, cached, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					// A new evaluation now drops. Later packet metadata must not
					// replace the first source decision when restoring the handoff.
					block := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)}
					if err := obj.RoutingMap.Update(uint32(0), block, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					deleteHandoff(t)
					laterPacket := append([]byte(nil), packet...)
					laterPacket[15] = 8 << 2
					laterPacket[11] ^= 1
					status, _, _, err = runBpfProgram(network.prog, laterPacket, ctx)
					if err != nil || status != 7 {
						t.Fatalf("cache hit: status=%d err=%v", status, err)
					}
					checkHandoff(t)
					if err := obj.UdpRoutingCacheMap.Lookup(cacheKey, &cached); err != nil || cached.CachedUntil == 0 || cached.CachedUntil == math.MaxUint64 {
						t.Fatalf("cache hit did not refresh idle expiry: %+v, err=%v", cached, err)
					}
					// Rebinding only affects new lifetimes. Even removing the old
					// profile must not interrupt a source that owns its first decision.
					if err := obj.RoutingInterfaceMap.Update(ifindex, directID, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					if err := obj.RoutingProfileMap.Delete(profileID); err != nil {
						t.Fatal(err)
					}
					deleteHandoff(t)
					status, _, _, err = runBpfProgram(network.prog, laterPacket, ctx)
					if err != nil || status != 7 {
						t.Fatalf("live source lost its route after rebinding: status=%d err=%v", status, err)
					}
					checkHandoff(t)
					// Idle expiry releases the source; the next packet now uses
					// the direct policy and must stay in the kernel.
					if err := obj.UdpRoutingCacheMap.Lookup(cacheKey, &cached); err != nil {
						t.Fatal(err)
					}
					cached.CachedUntil = 1
					if err := obj.UdpRoutingCacheMap.Update(cacheKey, cached, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					deleteHandoff(t)
					status, _, _, err = runBpfProgram(network.prog, packet, ctx)
					if err != nil || status != math.MaxUint32 { // TCX_NEXT: actual eBPF direct.
						t.Fatalf("new direct lifetime did not stay in the kernel: status=%d err=%v", status, err)
					}
					var result bpftestRoutingResult
					if err := obj.RoutingTuplesMap.Lookup(key, &result); !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("direct policy created a proxy handoff: %+v, err=%v", result, err)
					}
				})
			}
		})
	}
}
