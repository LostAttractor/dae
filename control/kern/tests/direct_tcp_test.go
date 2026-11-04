//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

func TestDirectTCPSynReplacesPreviousRoute(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	status, syn, ctx, err := runBpfProgram(obj.TestpktgenMacMatch, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil || status != 0 {
		t.Fatalf("generate SYN: status %d, error %v", status, err)
	}
	key := bpftestTuplesKey{Sport: nativeUint16(19233), Dport: nativeUint16(79), L4proto: unix.IPPROTO_TCP}
	key.Sip.U6Addr8 = netip.MustParseAddr("192.168.0.1").As16()
	key.Dip.U6Addr8 = netip.MustParseAddr("1.1.1.1").As16()
	ack := append([]byte(nil), syn...)
	// The fixture has Ethernet + IPv4 without options + TCP headers.
	ack[14+20+13] = 0x10
	const (
		direct       = 0
		proxy        = 2
		fallbackType = 11
		next         = math.MaxUint32 // TCX_NEXT
		redirect     = 7              // TC_ACT_REDIRECT
	)
	for _, test := range []struct {
		name        string
		previous    bpftestRoutingResult
		mark        uint32
		unavailable bool
		fallback    uint32
	}{
		{name: "proxy to plain direct", previous: bpftestRoutingResult{Outbound: proxy}},
		{name: "marked to plain direct", previous: bpftestRoutingResult{Outbound: direct, Mark: 42}},
		{name: "proxy to marked direct", previous: bpftestRoutingResult{Outbound: proxy}, mark: 73},
		{name: "proxy to unavailable selector direct fallback", previous: bpftestRoutingResult{Outbound: proxy}, unavailable: true},
		{name: "proxy to interruptible direct fallback", previous: bpftestRoutingResult{Outbound: proxy}, unavailable: true, fallback: 9},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.previous.Outbound == proxy {
				// A proxy SYN removed any direct flow; its pending setup owns the tuple.
				if err := obj.TcpFlowMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
				var now unix.Timespec
				if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
					t.Fatal(err)
				}
				handoff := bpftestRoutingHandoff{Result: test.previous, Expires: uint32(now.Sec) + 30}
				if err := obj.RoutingTuplesMap.Update(key, handoff, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			} else if err := obj.TcpFlowMap.Update(key, bpftestTcpFlowState{Mark: test.previous.Mark}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			fallback := bpftestMatchSet{Type: fallbackType, Outbound: direct, Mark: test.mark}
			if test.unavailable {
				fallback.Outbound = proxy
				query := bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
				if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{State: routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT, Fallback: test.fallback}, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if test.fallback != 0 {
				if err := obj.FallbackLeaseMap.Update(test.fallback, uint8(1), ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if err := obj.RoutingMap.Update(uint32(0), fallback, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			// Changing rules alone must preserve an already established flow.
			want := uint32(next)
			if test.previous.Outbound == proxy {
				want = redirect
			}
			if status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, ack, ctx); err != nil || status != want {
				t.Fatalf("existing ACK: status %d, error %v; want %d", status, err, want)
			}
			// An unavailable group degrades to direct in the kernel.
			advanceTCPSYN(syn, 34)
			for _, packet := range [][]byte{syn, ack} {
				status, _, ctxOut, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
				if err != nil || status != next {
					t.Fatalf("new direct flow: status %d, error %v", status, err)
				}
				// __sk_buff.mark is its third uint32 field.
				if mark := binary.NativeEndian.Uint32(ctxOut[8:12]); mark != test.mark {
					t.Fatalf("packet mark = %d, want %d", mark, test.mark)
				}
			}
			var result bpftestRoutingResult
			if err := lookupHandoff(obj.RoutingTuplesMap, key, &result); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("direct retained a setup handoff: %+v, %v", result, err)
			}
			var flow bpftestTcpFlowState
			err := obj.TcpFlowMap.Lookup(key, &flow)
			if err != nil || flow.Fallback != test.fallback || flow.Mark != test.mark {
				t.Fatalf("direct flow = %+v, %v", flow, err)
			}
			if test.fallback == 0 {
				return
			}
			// Recovery ends the fallback generation; its flows are rejected
			// like those of a changed device route.
			if err := obj.FallbackLeaseMap.Delete(test.fallback); err != nil {
				t.Fatal(err)
			}
			if status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, ack, ctx); err != nil || status != redirect {
				t.Fatalf("ended fallback ACK: status %d, error %v; want redirect to the rejecting listener", status, err)
			}
		})
	}
}

func TestFallbackRecoveryReroutesUDP(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	status, packet, ctx, err := runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil || status != 0 {
		t.Fatalf("generate packet: status %d, error %v", status, err)
	}
	const (
		proxy    = 2
		token    = uint32(7)
		next     = math.MaxUint32 // TCX_NEXT
		redirect = 7              // TC_ACT_REDIRECT
	)
	if err := obj.RoutingMap.Update(uint32(0), bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	query := bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_UDP, Ipversion: 4}
	if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{State: routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT, Fallback: token}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := obj.FallbackLeaseMap.Update(token, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
		t.Fatal(err)
	}
	run := func(want uint32) {
		t.Helper()
		if status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx); err != nil || status != want {
			t.Fatalf("status %d, error %v; want %d", status, err, want)
		}
	}
	run(next)
	var key bpftestUdpRoutingCacheKey
	var cached bpftestUdpRoutingCacheValue
	if iter := obj.UdpRoutingCacheMap.Iterate(); !iter.Next(&key, &cached) || cached.Result.Outbound != 0 || cached.Fallback != token {
		t.Fatalf("degraded source route = %+v", cached.Result)
	}
	// The source keeps its fallback decision until the generation ends.
	if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	run(next)
	if err := obj.FallbackLeaseMap.Delete(token); err != nil {
		t.Fatal(err)
	}
	run(redirect)
}

// A published fallback generation that has ended awaits its replacement, e.g.
// while a reload hands over. New flows go to userspace instead of joining it
// and being interrupted at their next packet.
func TestEndedFallbackGenerationHandsNewFlowsToUserspace(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	const (
		proxy    = 2
		token    = uint32(9)
		redirect = 7 // TC_ACT_REDIRECT
	)
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}})
	query := bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
	if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{State: routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT, Fallback: token}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	if status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx); err != nil || status != redirect {
		t.Fatalf("new flow of an ended generation: status %d, error %v; want redirect", status, err)
	}
	var result bpftestRoutingResult
	if err := lookupHandoff(obj.RoutingTuplesMap, key, &result); err != nil || result.Outbound != proxy {
		t.Fatalf("handoff = %+v, %v; want the group for userspace to degrade", result, err)
	}
}
