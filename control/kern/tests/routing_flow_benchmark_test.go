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

func BenchmarkRoutingConditionalBlock(b *testing.B) {
	for _, count := range []int{16, 128, 500} {
		for _, useBlock := range []bool{false, true} {
			for _, admitted := range []bool{false, true} {
				b.Run(fmt.Sprintf("block=%v/admitted=%v/rules=%d", useBlock, admitted, count), func(b *testing.B) {
					obj, err := loadTestObjects(b)
					if err != nil {
						b.Fatal(err)
					}
					packet, _, _ := routingFlowPacket(b, obj)
					port := uint16(1)
					if admitted {
						port = binary.BigEndian.Uint16(packet[36:38])
					}
					condition := routingPortRule(port, consts.MatchActionAnd, 0)
					var rules []bpftestMatchSet
					if useBlock {
						condition.Action, condition.Mark = uint8(consts.MatchActionConditionalJump), uint32(count+1)
						rules = append(rules, condition)
					}
					for range count {
						if !useBlock {
							rules = append(rules, condition)
						}
						rules = append(rules, routingPortRule(2, consts.MatchActionRoute, consts.OutboundBlock))
					}
					rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_Fallback)})
					installRoutingFlow(b, obj, rules)
					var runtimeTotal time.Duration
					for b.Loop() {
						status, duration, err := obj.TproxyWanEgressL2.Benchmark(packet, 1000, b.ResetTimer)
						if err != nil || status != ^uint32(0) {
							b.Fatalf("status=%d err=%v", status, err)
						}
						runtimeTotal += duration
					}
					b.ReportMetric(float64(runtimeTotal.Nanoseconds())/float64(b.N), "bpf-ns/op")
				})
			}
		}
	}
}

// A single hit terminates routing; repeated hits form an AND chain so the
// benchmark exercises every lookup. Misses traverse separate terminal rules.
func BenchmarkRoutingLPM(b *testing.B) {
	for _, count := range []int{1, 128} {
		for _, kind := range []struct {
			name      string
			matchType consts.MatchType
		}{
			{"destination", consts.MatchType_IpSet},
			{"source", consts.MatchType_SourceIpSet},
			{"mac", consts.MatchType_Mac},
		} {
			for _, hit := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/hit=%v/rules=%d", kind.name, hit, count), func(b *testing.B) {
					obj, err := loadTestObjects(b)
					if err != nil {
						b.Fatal(err)
					}
					packet, _, tuple := routingFlowPacket(b, obj)
					key := struct {
						PrefixLen uint32
						Address   [16]byte
					}{PrefixLen: 128}
					switch kind.matchType {
					case consts.MatchType_IpSet:
						key.Address = tuple.Dip.U6Addr8
					case consts.MatchType_SourceIpSet:
						key.Address = tuple.Sip.U6Addr8
					case consts.MatchType_Mac:
						copy(key.Address[10:], packet[6:12])
					}
					if hit {
						if err := obj.UnusedLpmType.Update(key, uint32(1), ebpf.UpdateAny); err != nil {
							b.Fatal(err)
						}
					}
					// Prove the key matches before using AND, whose miss would
					// otherwise skip to the same direct fallback and hide a bad fixture.
					installRoutingFlow(b, obj, []bpftestMatchSet{
						{Type: uint8(kind.matchType), Outbound: uint8(consts.OutboundBlock)},
						{Type: uint8(consts.MatchType_Fallback)},
					})
					want := ^uint32(0)
					if hit {
						want = 2 // TC_ACT_SHOT
					}
					if status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, nil); err != nil || status != want {
						b.Fatalf("LPM fixture: status=%d want=%d err=%v", status, want, err)
					}
					rules := make([]bpftestMatchSet, count+1)
					for i := range count {
						rules[i] = bpftestMatchSet{Type: uint8(kind.matchType), Outbound: uint8(consts.OutboundBlock)}
						if hit && count > 1 {
							rules[i].Action = uint8(consts.MatchActionAnd)
						} else if hit {
							rules[i].Outbound = uint8(consts.OutboundDirect)
						}
					}
					rules[count] = bpftestMatchSet{Type: uint8(consts.MatchType_Fallback)}
					installRoutingFlow(b, obj, rules)
					var runtimeTotal time.Duration
					for b.Loop() {
						status, duration, err := obj.TproxyWanEgressL2.Benchmark(packet, 1000, b.ResetTimer)
						if err != nil || status != ^uint32(0) {
							b.Fatalf("status=%d err=%v", status, err)
						}
						runtimeTotal += duration
					}
					b.ReportMetric(float64(runtimeTotal.Nanoseconds())/float64(b.N), "bpf-ns/op")
				})
			}
		}
	}
}

// The legacy fixture also runs against an object built before HTTP entry conditions.
// Both blocks miss their domains, so timing excludes userspace handoff and
// measures the cost of admission plus traversing or skipping capture rules.
func BenchmarkHTTPClientAdmission(b *testing.B) {
	for _, count := range []int{16, 128, 1000} {
		for _, scenario := range []string{"legacy", "denied", "allowed"} {
			b.Run(fmt.Sprintf("%s/rules=%d", scenario, count), func(b *testing.B) {
				obj, err := loadTestObjects(b)
				if err != nil {
					b.Fatal(err)
				}
				packet, _, _ := routingFlowPacket(b, obj)
				allow := uint32(0)
				if scenario == "allowed" {
					allow = 1
				}
				if err := obj.UnusedHttpClients.Update(bpftestHttpClientKey{Prefixlen: 32}, bpftestHttpClientDecision{Order: 1, Allow: allow}, ebpf.UpdateAny); err != nil {
					b.Fatal(err)
				}
				var rules []bpftestMatchSet
				for _, flags := range []uint8{5, 1} {
					if scenario != "legacy" {
						rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_HTTPClient), Action: uint8(consts.MatchActionConditionalJump), Mark: uint32(count/2 + 1)})
					}
					for i := range count / 2 {
						rule := routingDomainRule(uint32(i), consts.MatchActionCapture, 0)
						rule.Flags = flags << 3
						rules = append(rules, rule)
					}
				}
				rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_Fallback)})
				installRoutingFlow(b, obj, rules)
				var runtimeTotal time.Duration
				for b.Loop() {
					status, perRun, err := obj.TproxyWanEgressL2.Benchmark(packet, 1000, b.ResetTimer)
					if err != nil || status != ^uint32(0) {
						b.Fatalf("expected kernel direct: status=%d err=%v", status, err)
					}
					runtimeTotal += perRun
				}
				b.ReportMetric(float64(runtimeTotal.Nanoseconds())/float64(b.N), "bpf-ns/op")
			})
		}
	}
}

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
