//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"math"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

func TestStoppingEntryAndExit(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	run := func(p *ebpf.Program, packet []byte, want uint32) {
		t.Helper()
		got, _, _, err := runBpfProgram(p, packet, ctx)
		if err != nil || got != want {
			t.Fatalf("verdict %d, want %d: %v", got, want, err)
		}
	}
	set := func(value uint8) { must(obj.ExitedMap.Update(uint32(0), value, ebpf.UpdateAny)) }
	route := func(outbound uint8, capture uint8) {
		_ = obj.TcpFlowMap.Delete(key)
		_ = obj.RoutingTuplesMap.Delete(key)
		rules := []bpftestMatchSet{}
		if capture != 0 {
			rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_L4Proto), Value: [16]byte{byte(consts.L4ProtoType_TCP)}, Flags: capture << 3, Action: uint8(consts.MatchActionCapture)})
		}
		rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: outbound})
		installRoutingFlow(t, obj, rules)
	}
	const next = math.MaxUint32
	const drop = 2
	route(2, 0)
	set(routingabi.DAEMON_STOPPING)
	must(obj.DaemonIdentityMap.Update(uint32(0), uint64(os.Getpid()), ebpf.UpdateAny))
	run(obj.TproxyWanEgressL2, packet, drop)
	run(obj.TestDaemonExit, packet, next)
	var identity uint64
	must(obj.DaemonIdentityMap.Lookup(uint32(0), &identity))
	if identity != 0 {
		t.Fatal("stopping exit kept daemon PID registration")
	}
	var state uint8
	must(obj.ExitedMap.Lookup(uint32(0), &state))
	if state != routingabi.DAEMON_STOPPING {
		t.Fatalf("exit overwrote stopping: %d", state)
	}
	run(obj.TproxyWanEgressL2, packet, drop)
	// Even configured no-alive fallback must not turn shutdown into direct.
	must(obj.OutboundConnectivityMap.Update(bpftestOutboundConnectivityQuery{Outbound: 2, L4proto: unix.IPPROTO_TCP, Ipversion: 4}, bpftestOutboundConnectivity{State: routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT}, ebpf.UpdateAny))
	run(obj.TproxyWanEgressL2, packet, drop)
	route(0, routingabi.CAPTURE_HTTP)
	run(obj.TproxyWanEgressL2, packet, drop)
	route(0, 0)
	run(obj.TproxyWanEgressL2, packet, next)
	ack := append([]byte(nil), packet...)
	ack[14+20+13] = 0x10
	run(obj.TproxyWanEgressL2, ack, next)
	set(routingabi.DAEMON_ONLINE)
	run(obj.TestDaemonExit, packet, next)
	must(obj.ExitedMap.Lookup(uint32(0), &state))
	if state != routingabi.DAEMON_OFFLINE {
		t.Fatalf("unexpected exit state %d", state)
	}
	route(2, 0)
	run(obj.TproxyWanEgressL2, packet, next)
	// A normal restart retains next's native semantics for unknown non-SYNs.
	set(routingabi.DAEMON_ONLINE)
	_ = obj.TcpFlowMap.Delete(key)
	run(obj.TproxyWanEgressL2, ack, next)
	route(0, 0)
	run(obj.TproxyWanEgressL2, packet, next)
	run(obj.TproxyWanEgressL2, ack, next)
	// Replies to newly observed inbound SYNs are still allowed.
	_ = obj.TcpFlowMap.Delete(key)
	incoming := append([]byte(nil), packet...)
	copy(incoming[26:30], packet[30:34])
	copy(incoming[30:34], packet[26:30])
	copy(incoming[34:36], packet[36:38])
	copy(incoming[36:38], packet[34:36])
	run(obj.TproxyWanIngressL2, incoming, next)
	run(obj.TproxyWanEgressL2, ack, next)
}

func TestReplacementGuardChainMayPauseDirectTCP(t *testing.T) {
	for _, name := range []string{"LAN", "WAN"} {
		t.Run(name, func(t *testing.T) {
			old, err := loadTestObjects(t, "LanIngressL2", "TproxyWanEgressL2", "TestpktgenMacMatch")
			if err != nil {
				t.Fatal(err)
			}
			next, err := loadTestObjects(t, "LanIngressL2", "TproxyWanEgressL2", "TestDaemonExit")
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			oldEntry, nextEntry := old.LanIngressL2, next.LanIngressL2
			if name == "WAN" {
				oldEntry, nextEntry = old.TproxyWanEgressL2, next.TproxyWanEgressL2
			}
			rules := []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect)}}
			installRoutingFlow(t, old, rules)
			installRoutingFlow(t, next, rules)
			packet, ctx, key := routingFlowPacket(t, old)
			run := func(want uint32, programs ...*ebpf.Program) {
				t.Helper()
				data, context := packet, ctx
				var got uint32
				var err error
				for _, program := range programs {
					got, data, context, err = runBpfProgram(program, data, context)
					must(err)
					if got != math.MaxUint32 {
						break
					}
				}
				if got != want {
					t.Fatalf("guard chain verdict=%d, want %d", got, want)
				}
			}
			run(math.MaxUint32, oldEntry)
			var direct bpftestTcpFlowState
			must(old.TcpFlowMap.Lookup(key, &direct))
			if direct.ExplicitDirect != 1 {
				t.Fatal("old generation did not record explicit direct")
			}
			must(old.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny))
			must(next.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny))
			packet[14+20+13] = 0x10
			// Only the old map knows this flow. NEXT must not bypass later TCX programs.
			run(math.MaxUint32, oldEntry)
			run(2, oldEntry, nextEntry)
			// A failed successor retains the barrier rather than guessing ownership.
			must(next.DaemonIdentityMap.Update(uint32(0), uint64(os.Getpid()), ebpf.UpdateAny))
			run(math.MaxUint32, next.TestDaemonExit)
			run(2, oldEntry, nextEntry)
			must(old.TcpFlowMap.Delete(key))
			run(2, oldEntry)
			revoked := direct
			revoked.Fallback = 2
			must(old.TcpFlowMap.Update(key, revoked, ebpf.UpdateAny))
			run(2, oldEntry)
			must(old.TcpFlowMap.Update(key, direct, ebpf.UpdateAny))
			// After old guards retire, ordinary restart semantics resume.
			must(next.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_ONLINE), ebpf.UpdateAny))
			run(math.MaxUint32, nextEntry)
		})
	}
}

func TestStoppingUDPAndFragments(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, gen := range []*ebpf.Program{obj.TestpktgenUdpRouteCacheMiss, obj.TestpktgenParserIpv6Udp} {
		_, packet, ctx, err := runBpfProgram(gen, make([]byte, 4096-256-320), make([]byte, 256))
		if err != nil {
			t.Fatal(err)
		}
		for _, outbound := range []uint8{0, 2} {
			if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
				t.Fatal(err)
			}
			installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: outbound}})
			if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			want := uint32(2)
			if outbound == 0 {
				want = math.MaxUint32
			}
			got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
			if err != nil || got != want {
				t.Fatalf("UDP outbound=%d verdict=%d want=%d: %v", outbound, got, want, err)
			}
		}
	}
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: 0}})
	for _, gen := range []*ebpf.Program{obj.TestpktgenIpv4FirstUdpFragmentDirect, obj.TestpktgenIpv6FirstUdpFragmentDirect} {
		_, first, ctx, err := runBpfProgram(gen, make([]byte, 4096-256-320), make([]byte, 256))
		if err != nil {
			t.Fatal(err)
		}
		// A new direct datagram has 16 payload bytes in its first fragment
		// and eight in its last. Replacement must not permanently break it.
		last := append([]byte(nil), first[:len(first)-8]...)
		if gen == obj.TestpktgenIpv4FirstUdpFragmentDirect {
			binary.BigEndian.PutUint16(last[16:18], 20+8)
			binary.BigEndian.PutUint16(last[20:22], 2)
		} else {
			binary.BigEndian.PutUint16(last[18:20], 8+8)
			binary.BigEndian.PutUint16(last[56:58], 16)
		}
		for _, state := range []uint8{routingabi.DAEMON_STOPPING, routingabi.DAEMON_ONLINE} {
			if err := obj.ExitedMap.Update(uint32(0), state, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, first, ctx)
			if err != nil || got != math.MaxUint32 {
				t.Fatalf("direct first fragment: verdict=%d state=%d err=%v", got, state, err)
			}
			want := uint32(math.MaxUint32)
			if state == routingabi.DAEMON_STOPPING {
				want = 2
			}
			got, _, _, err = runBpfProgram(obj.TproxyWanEgressL2, last, ctx)
			if err != nil || got != want {
				t.Fatalf("direct final fragment: verdict=%d want=%d state=%d err=%v", got, want, state, err)
			}
		}
	}
}

func TestStoppingRequiresExplicitDirect(t *testing.T) {
	obj, err := loadTestObjects(t, "TproxyWanEgressL2", "TestpktgenMacMatch")
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	packet[47] = 0x10
	for _, stored := range []bool{false, true} {
		if stored {
			// An old pin's padding and zero fallback are not proof of explicit direct.
			if err := obj.TcpFlowMap.Update(key, bpftestTcpFlowState{}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
		}
		for _, state := range []uint8{routingabi.DAEMON_ONLINE, routingabi.DAEMON_STOPPING} {
			if err := obj.ExitedMap.Update(uint32(0), state, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			want := uint32(tcxNext)
			if state == routingabi.DAEMON_STOPPING {
				want = 2
			}
			got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
			if err != nil || got != want {
				t.Fatalf("stored=%v state=%d verdict=%d want=%d: %v", stored, state, got, want, err)
			}
		}
	}
}

func TestStoppingDoesNotSkipProxyToDirect(t *testing.T) {
	obj, err := loadTestObjects(t, "TproxyWanEgressL2", "TestpktgenMacMatch")
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	installRoutingFlow(t, obj, []bpftestMatchSet{
		{Type: uint8(consts.MatchType_L4Proto), Value: [16]byte{byte(consts.L4ProtoType_TCP)}, Flags: routingabi.MATCH_FLAG_SKIP_NOALIVE, Outbound: 2},
		{Type: uint8(consts.MatchType_Fallback), Outbound: 0},
	})
	query := bpftestOutboundConnectivityQuery{Outbound: 2, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
	for _, connectivity := range []uint32{routingabi.OUTBOUND_CONNECTIVITY_ALIVE, routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT} {
		if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{State: connectivity}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
		if err != nil || got != 2 {
			t.Fatalf("connectivity=%d verdict=%d: %v", connectivity, got, err)
		}
	}
	// A skip-to-direct cached while online is still a degraded decision.
	if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_ONLINE), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx); err != nil || got != tcxNext {
		t.Fatalf("online skipped route: verdict=%d: %v", got, err)
	}
	var flow bpftestTcpFlowState
	if err := obj.TcpFlowMap.Lookup(key, &flow); err != nil || flow.ExplicitDirect != 0 {
		t.Fatalf("skipped route became explicit direct: %+v: %v", flow, err)
	}
	if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	packet[47] = 0x10
	if got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx); err != nil || got != 2 {
		t.Fatalf("cached skipped route: verdict=%d: %v", got, err)
	}
}

func TestStoppingBindingPrecedesDNSBypass(t *testing.T) {
	obj, err := loadTestObjects(t, "TproxyWanEgressL2", "TestpktgenUdpRouteCacheMiss")
	if err != nil {
		t.Fatal(err)
	}
	_, packet, ctx, err := runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, make([]byte, 3520), make([]byte, 256))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(packet[36:38], 53)
	installRoutingFlow(t, obj, []bpftestMatchSet{
		{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMust)},
		{Type: uint8(consts.MatchType_Fallback), Outbound: 0},
	})
	if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	key := bpftestUdpRoutingCacheKey{Sport: binary.NativeEndian.Uint16(packet[34:36])}
	key.Sip.U6Addr8 = netip.AddrFrom4([4]byte(packet[26:30])).As16()
	if err := obj.UdpBindingsMap.Update(key, bpftestUdpBinding{SourceOrigin: uint8(plugin.SourceLocal)}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx); err != nil || got != 2 {
		t.Fatalf("bound DNS source escaped: verdict=%d: %v", got, err)
	}
}

func TestStoppingDirectDNSUsesCurrentPolicyMark(t *testing.T) {
	obj, err := loadTestObjects(t, "TproxyWanEgressL2", "TestpktgenUdpRouteCacheMiss")
	if err != nil {
		t.Fatal(err)
	}
	_, packet, ctx, err := runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, make([]byte, 3520), make([]byte, 256))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(packet[36:38], 53)
	if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	direct := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Mark: 10}
	run := func(rules ...bpftestMatchSet) {
		t.Helper()
		installRoutingFlow(t, obj, rules)
		got, _, result, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
		if err != nil || got != tcxNext {
			t.Fatalf("direct DNS verdict=%d: %v", got, err)
		}
		if mark := binary.NativeEndian.Uint32(result[8:12]); mark != direct.Mark {
			t.Fatalf("direct DNS mark=%d, want current rule's %d", mark, direct.Mark)
		}
	}
	// A must route establishes a source association. A bypass rule owns its own mark.
	run(bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMust)}, direct)
	direct.Mark, direct.Flags = 11, routingabi.MATCH_FLAG_BYPASS
	run(direct)
}

func TestStoppingRelayOnlyAllowsReset(t *testing.T) {
	obj, err := loadTestObjects(t, "TproxyDae0Ingress", "TestpktgenMacMatch")
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, _ := routingFlowPacket(t, obj)
	binary.NativeEndian.PutUint32(ctx[48:52], daeReplyMark)
	if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, flags := range []byte{0x10, 0x11, 0x14} {
		packet[47] = flags
		want := uint32(2)
		if flags&4 != 0 {
			want = 0
		}
		if got, _, _, err := runBpfProgram(obj.TproxyDae0Ingress, packet, ctx); err != nil || got != want {
			t.Fatalf("relay flags=%#x verdict=%d want=%d: %v", flags, got, want, err)
		}
	}
}
