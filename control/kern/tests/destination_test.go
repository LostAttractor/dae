//go:build linux && dae_bpf_tests

package tests

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func TestDestinationCapturePreservesRoute(t *testing.T) {
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
		capture := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: 0, CaptureFlags: 2}
		route := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: outbound, Mark: 37, Must: true}
		if err := obj.RoutingMap.Update(uint32(0), capture, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := obj.RoutingMap.Update(uint32(1), route, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
		want := uint32(7)
		if outbound == 1 {
			want = 2
		}
		if err != nil || status != want {
			t.Fatalf("outbound=%d status=%d err=%v", outbound, status, err)
		}
		if outbound != 1 {
			var result bpftestRoutingResult
			if err := obj.RoutingTuplesMap.Lookup(key, &result); err != nil {
				t.Fatal(err)
			}
			if result.Outbound != outbound || result.Mark != 37 || result.Must != 1 || result.CaptureFlags != 2 {
				t.Fatalf("lost route: %+v", result)
			}
		}
	}
}
