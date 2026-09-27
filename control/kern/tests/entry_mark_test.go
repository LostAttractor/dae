//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func TestEntrySocketMarksPreserveKernelBypass(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	// A mark must not identify arbitrary client traffic as daemon traffic.
	rule := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)}
	if err := obj.RoutingMap.Update(uint32(0), rule, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, pktgen := range []*ebpf.Program{obj.TestpktgenMacMatch, obj.TestpktgenUdpRouteCacheMiss, obj.TestpktgenParserIpv6Udp} {
		status, packet, ctx, err := runBpfProgram(pktgen, make([]byte, 4096-256-320), make([]byte, 256))
		if err != nil || status != 0 {
			t.Fatalf("packet generation: %d, %v", status, err)
		}
		for _, mark := range []uint32{0, 0x20, 0x100, 0x80000000} {
			for _, daemon := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/mark=%x/daemon=%v", pktgen, mark, daemon), func(t *testing.T) {
					program := obj.TestEntryMarkDaemon
					want := ^uint32(0) // TCX_NEXT.
					if !daemon {
						program = obj.TestEntryMarkOther
						want = 2 // TCX_DROP.
					}
					if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
						t.Fatal(err)
					}
					binary.NativeEndian.PutUint32(ctx[8:12], mark) // __sk_buff.mark.
					status, _, output, err := runBpfProgram(program, packet, ctx)
					if err != nil || status != want {
						t.Fatalf("kernel decision = %d, %v; want %d", status, err, want)
					}
					if daemon && binary.NativeEndian.Uint32(output[8:12]) != mark {
						t.Fatal("kernel bypass rewrote the entry socket mark")
					}
				})
			}
		}
	}
}
