//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

// TCP SYNs always evaluate routing and direct does not create a cache entry.
// This isolates instruction traversal from UDP cache hits and userspace handoff.
func BenchmarkRoutingFlow(b *testing.B) {
	for _, count := range []int{16, 128, 1024} {
		for _, scenario := range []string{"domain-missing", "domain-empty", "and-short-circuit", "or-short-circuit", "port-sequential"} {
			b.Run(fmt.Sprintf("%s/rules=%d", scenario, count), func(b *testing.B) {
				obj, err := loadTestObjects(b)
				if err != nil {
					b.Fatal(err)
				}
				packet, ctx, key := routingFlowPacket(b, obj)
				rules := make([]bpftestMatchSet, count)
				for i := range rules {
					rules[i] = routingDomainRule(uint32(i), consts.MatchActionRoute, consts.OutboundBlock)
				}
				rules[count-1] = bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect)}
				switch scenario {
				case "port-sequential":
					for i := 0; i < count-1; i++ {
						rules[i] = routingPortRule(1, consts.MatchActionRoute, consts.OutboundBlock)
					}
				case "domain-empty":
					if err := obj.DomainRoutingMap.Update(key.Dip.U6Addr8, bpftestDomainRouting{}, ebpf.UpdateAny); err != nil {
						b.Fatal(err)
					}
				case "and-short-circuit":
					rules[0] = routingPortRule(1, consts.MatchActionAnd, 0)
					for i := 1; i < count-2; i++ {
						rules[i].Action = uint8(consts.MatchActionAnd)
					}
				case "or-short-circuit":
					rules[0] = routingPortRule(binary.BigEndian.Uint16(packet[36:38]), consts.MatchActionOr, 0)
					for i := 1; i < count-2; i++ {
						rules[i].Action = uint8(consts.MatchActionOr)
					}
					rules[count-2].Outbound = uint8(consts.OutboundDirect)
					rules[count-1].Outbound = uint8(consts.OutboundBlock)
				}
				installRoutingFlow(b, obj, rules)
				// Benchmark cannot pass a custom skb context. Verify that this
				// default-policy packet follows the same path with either input.
				for _, inputCtx := range [][]byte{ctx, nil} {
					status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, inputCtx)
					if err != nil || status != ^uint32(0) {
						b.Fatalf("expected kernel direct before timing: status=%d err=%v", status, err)
					}
				}
				var runtimeTotal time.Duration
				b.ResetTimer()
				for range b.N {
					status, perRun, err := obj.TproxyWanEgressL2.Benchmark(packet, 1000, b.ResetTimer)
					if err != nil || status != ^uint32(0) {
						b.Fatalf("expected kernel direct during timing: status=%d err=%v", status, err)
					}
					runtimeTotal += perRun
				}
				b.ReportMetric(float64(runtimeTotal.Nanoseconds())/float64(max(b.N, 1)), "bpf-ns/op")
				var route bpftestRoutingResult
				if err := lookupHandoff(obj.RoutingTuplesMap, key, &route); !errors.Is(err, ebpf.ErrKeyNotExist) {
					b.Fatalf("direct benchmark created proxy state: %+v, %v", route, err)
				}
			})
		}
	}
}
