//go:build linux && dae_bpf_tests

package tests

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func TestDestinationCaptureDefersRoute(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	_, packet, ctx, err := runBpfProgram(obj.TestpktgenMacMatch, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil {
		t.Fatal(err)
	}
	key := bpftestTuplesKey{Sport: nativeUint16(19233), Dport: nativeUint16(79), L4proto: 6}
	key.Sip.U6Addr8 = netip.MustParseAddr("192.168.0.1").As16()
	key.Dip.U6Addr8 = netip.MustParseAddr("1.1.1.1").As16()
	for _, outbound := range []uint8{0, 1, 2} {
		capture := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: 0, Flags: (2) << 3, Action: uint8(consts.MatchActionCapture)}
		route := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: outbound, Mark: 37, Flags: 1 << 1}
		if err := obj.RoutingMap.Update(uint32(0), capture, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := obj.RoutingMap.Update(uint32(1), route, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
		want := uint32(7)
		if err != nil || status != want {
			t.Fatalf("outbound=%d status=%d err=%v", outbound, status, err)
		}
		{
			var result bpftestRoutingResult
			if err := obj.RoutingTuplesMap.Lookup(key, &result); err != nil {
				t.Fatal(err)
			}
			if result.Outbound != uint8(consts.OutboundControlPlaneRouting) || result.Mark != 0 || result.Must != 0 || result.CaptureFlags != 2 {
				t.Fatalf("old target route committed before rewriting: %+v", result)
			}
		}
	}
}

func TestDestinationUDPOwnershipSurvivesRuleRemoval(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	_, packet, ctx, err := runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil {
		t.Fatal(err)
	}
	key := bpftestUdpRoutingCacheKey{Sport: binary.NativeEndian.Uint16(packet[34:36])}
	key.Sip.U6Addr8 = netip.AddrFrom4([4]byte(packet[26:30])).As16()
	if err := obj.UdpBindingsMap.Update(key, uint64(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := obj.RoutingMap.Update(uint32(0), bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: 0}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
	if err != nil || status != 7 {
		t.Fatalf("lost owned association: %d %v", status, err)
	}
	if err := obj.UdpBindingsMap.Delete(key); err != nil {
		t.Fatal(err)
	}
	status, _, _, err = runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
	if err != nil || status != ^uint32(0) {
		t.Fatalf("released association did not return to normal routing: %d %v", status, err)
	}
}
