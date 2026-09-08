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

func TestRoutingProfileReplacementAndBounds(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	_, packet, ctx, err := runBpfProgram(obj.TestpktgenMacMatch, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil {
		t.Fatal(err)
	}
	ifindex := binary.NativeEndian.Uint32(ctx[40:44])
	const profileID = uint32(0xfffffff0)
	if err := obj.RoutingInterfaceMap.Update(ifindex, profileID, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	// Default allows direct; the selected profile must never silently fall
	// back to it if its value is missing, malformed, or exhausted.
	direct := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback)}
	block := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: 1}
	miss := bpftestMatchSet{Type: uint8(consts.MatchType_Port)}
	if err := obj.RoutingMap.Update(uint32(0), direct, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := obj.RoutingMap.Update(uint32(1), miss, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	last := obj.RoutingMap.MaxEntries() - 1
	if err := obj.RoutingMap.Update(last, block, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		length  uint32
		steps   []uint16
		missing bool
		want    uint32
	}{
		{name: "missing", missing: true, want: 2},
		{name: "empty", length: 0, want: 2},
		{name: "too_long", length: obj.RoutingMap.MaxEntries() + 1, want: 2},
		{name: "invalid_index", length: 1, steps: []uint16{uint16(last + 1)}, want: 2},
		{name: "last_physical_index", length: 1, steps: []uint16{uint16(last)}, want: 2},
		{name: "replace_direct", length: 1, steps: []uint16{0}, want: ^uint32(0)},
		{name: "shortened_without_terminal", length: 1, steps: []uint16{1, 0}, want: 2},
		{name: "extended_with_terminal", length: 2, steps: []uint16{1, 0}, want: ^uint32(0)},
		{name: "replace_block", length: 1, steps: []uint16{uint16(last)}, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.missing {
				profile := bpftestRoutingProfile{Length: tc.length}
				copy(profile.Steps[:], tc.steps)
				if err := obj.RoutingProfileMap.Update(profileID, profile, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
			if err != nil || status != tc.want {
				t.Fatalf("status = %d, want %d, error = %v", status, tc.want, err)
			}
		})
	}
}

func TestNamedDefaultPolicySwitch(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	// Both policies share capture, with separate fallbacks. New lifetimes use
	// the selected policy; a live UDP source keeps its original profile.
	for index, rule := range []bpftestMatchSet{
		{Type: uint8(consts.MatchType_Fallback), Flags: 2 << 3, Action: uint8(consts.MatchActionCapture)},
		{Type: uint8(consts.MatchType_Fallback), Mark: 11},
		{Type: uint8(consts.MatchType_Fallback), Mark: 22},
	} {
		if err := obj.RoutingMap.Update(uint32(index), rule, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	const first, second = uint32(70001), uint32(70002)
	for id, step := range map[uint32]uint16{first: 1, second: 2} {
		profile := bpftestRoutingProfile{Length: 2}
		profile.Steps[0], profile.Steps[1] = 0, step
		if err := obj.RoutingProfileMap.Update(id, profile, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for _, network := range []struct {
		name     string
		pktgen   *ebpf.Program
		protocol uint8
		retained bool
	}{
		{"TCP", obj.TestpktgenMacMatch, 6, false},
		{"UDP fresh source", obj.TestpktgenUdpRouteCacheMiss, 17, false},
		{"UDP retained source", obj.TestpktgenUdpRouteCacheMiss, 17, true},
	} {
		t.Run(network.name, func(t *testing.T) {
			_, packet, ctx, err := runBpfProgram(network.pktgen, make([]byte, 4096-256-320), make([]byte, 256))
			if err != nil {
				t.Fatal(err)
			}
			ifindex := binary.NativeEndian.Uint32(ctx[40:44])
			key := bpftestTuplesKey{L4proto: network.protocol}
			key.Sip.U6Addr8 = netip.AddrFrom4([4]byte(packet[26:30])).As16()
			key.Dip.U6Addr8 = netip.AddrFrom4([4]byte(packet[30:34])).As16()
			key.Sport = binary.NativeEndian.Uint16(packet[34:36])
			key.Dport = binary.NativeEndian.Uint16(packet[36:38])
			source := bpftestUdpRoutingCacheKey{Sip: key.Sip, Sport: key.Sport}
			if network.protocol == 17 {
				_ = obj.UdpRoutingCacheMap.Delete(source)
			}
			for _, tc := range []struct {
				name                                 string
				defaultID, binding, wantID, wantMark uint32
			}{
				{"default", first, 0, first, 11},
				{"switch default with live caches", second, 0, second, 22},
				{"interface overrides default", second, first, first, 11},
				{"default and interface share policy", second, second, second, 22},
				{"remove binding", first, 0, first, 11},
				{"missing default fails closed", 99999, 0, 0, 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if err := obj.DefaultRoutingProfile.Set(tc.defaultID); err != nil {
						t.Fatal(err)
					}
					if tc.binding == 0 {
						if err := obj.RoutingInterfaceMap.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatal(err)
						}
					} else if err := obj.RoutingInterfaceMap.Update(ifindex, tc.binding, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					if network.protocol == 17 && !network.retained {
						if err := obj.UdpRoutingCacheMap.Delete(source); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatal(err)
						}
					}
					wantID := tc.wantID
					if network.retained {
						wantID = first
					}
					status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
					want := uint32(7)
					if wantID == 0 {
						want = 2
					}
					if err != nil || status != want {
						t.Fatalf("status=%d want=%d err=%v", status, want, err)
					}
					if wantID == 0 {
						return
					}
					var result bpftestRoutingResult
					if err := obj.RoutingTuplesMap.Lookup(key, &result); err != nil {
						t.Fatal(err)
					}
					if result.ProfileId != wantID || result.Mark != 0 || result.Outbound != uint8(consts.OutboundControlPlaneRouting) {
						t.Fatalf("wrong policy decision: %+v", result)
					}
				})
			}
		})
	}
}
