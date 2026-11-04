//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

// First fragments of fallback flows follow their generation like whole
// packets: a degraded flow records its token, and an ended token rejects a
// TCP flow and re-routes a UDP source.
func TestFallbackGenerationEndsFirstFragments(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	const (
		proxy = 2
		token = uint32(11)
		next  = math.MaxUint32 // TCX_NEXT
		drop  = 2              // TCX_DROP
	)
	run := func(t *testing.T, prog *ebpf.Program, packet, ctx []byte, want uint32) {
		t.Helper()
		if status, _, _, err := runBpfProgram(prog, packet, ctx); err != nil || status != want {
			t.Fatalf("status %d, error %v; want %d", status, err, want)
		}
	}
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}})
	t.Run("TCP", func(t *testing.T) {
		_, packet, ctx, err := runBpfProgram(obj.TestpktgenIpv4FirstFragmentDirect, make([]byte, 4096-256-320), make([]byte, 256))
		if err != nil {
			t.Fatal(err)
		}
		query := bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
		if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{State: routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT, Fallback: token}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := obj.FallbackLeaseMap.Update(token, uint8(1), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		packet[14+20+13] = 0x02 // The flow's SYN.
		run(t, obj.TproxyWanEgressL2, packet, ctx, next)
		key := bpftestTuplesKey{Sport: nativeUint16(19310), Dport: nativeUint16(80), L4proto: unix.IPPROTO_TCP}
		key.Sip.U6Addr8, key.Dip.U6Addr8 = netip.MustParseAddr("192.168.0.10").As16(), netip.MustParseAddr("1.1.1.10").As16()
		var flow bpftestTcpFlowState
		if err := obj.TcpFlowMap.Lookup(key, &flow); err != nil || flow.Fallback != token {
			t.Fatalf("degraded flow = %+v, %v; want token %d", flow, err, token)
		}
		packet[14+20+13] = 0x10 // An established flow's ACK.
		run(t, obj.TproxyWanEgressL2, packet, ctx, next)
		if err := obj.FallbackLeaseMap.Delete(token); err != nil {
			t.Fatal(err)
		}
		run(t, obj.TproxyWanEgressL2, packet, ctx, drop)
	})
	t.Run("UDP", func(t *testing.T) {
		_, packet, ctx, err := runBpfProgram(obj.TestpktgenIpv4FirstUdpFragmentDirect, make([]byte, 4096-256-320), make([]byte, 256))
		if err != nil {
			t.Fatal(err)
		}
		if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
			t.Fatal(err)
		}
		query := bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_UDP, Ipversion: 4}
		if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{State: routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT, Fallback: token}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := obj.FallbackLeaseMap.Update(token, uint8(1), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		run(t, obj.LanIngressL2, packet, ctx, next)
		var key bpftestUdpRoutingCacheKey
		var cached bpftestUdpRoutingCacheValue
		if iter := obj.UdpRoutingCacheMap.Iterate(); !iter.Next(&key, &cached) || cached.Fallback != token {
			t.Fatalf("degraded source route = %+v", cached.Result)
		}
		// The group recovered: its source is routed again, to the proxy, which
		// cannot take only the first fragment of a datagram.
		if err := obj.FallbackLeaseMap.Delete(token); err != nil {
			t.Fatal(err)
		}
		if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		run(t, obj.LanIngressL2, packet, ctx, drop)
	})
}
