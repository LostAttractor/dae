//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

func TestStoppingControlProtocols(t *testing.T) {
	obj, err := loadTestObjects(t, "LanIngressL2", "TproxyWanEgressL2", "TestpktgenMacMatch")
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, _ := routingFlowPacket(t, obj)
	arp := make([]byte, 42)
	copy(arp[:12], packet[:12])
	binary.BigEndian.PutUint16(arp[12:14], unix.ETH_P_ARP)
	binary.BigEndian.PutUint16(arp[14:16], 1)
	binary.BigEndian.PutUint16(arp[16:18], unix.ETH_P_IP)
	arp[18], arp[19] = 6, 4
	binary.BigEndian.PutUint16(arp[20:22], 1)
	icmp := append([]byte(nil), packet[:42]...)
	icmp[23] = unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(icmp[16:18], 28)
	icmp[34] = 8
	malformed := append([]byte(nil), packet...)
	malformed[46] = 0
	for _, state := range []uint8{routingabi.DAEMON_ONLINE, routingabi.DAEMON_STOPPING} {
		if err := obj.ExitedMap.Update(uint32(0), state, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
			for _, test := range []struct {
				packet []byte
				want   uint32
			}{{arp, math.MaxUint32}, {icmp, math.MaxUint32}, {arp[:30], 2}, {malformed, 2}} {
				got, _, _, err := runBpfProgram(program, test.packet, ctx)
				if err != nil || got != test.want {
					t.Fatalf("state=%d verdict=%d want=%d: %v", state, got, test.want, err)
				}
			}
		}
	}
}

func TestStoppingCachedPermanentFallback(t *testing.T) {
	for _, protocol := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		t.Run(map[uint8]string{unix.IPPROTO_TCP: "TCP", unix.IPPROTO_UDP: "UDP"}[protocol], func(t *testing.T) {
			obj, err := loadTestObjects(t, "TproxyWanEgressL2", "TestpktgenMacMatch", "TestpktgenUdpRouteCacheMiss")
			if err != nil {
				t.Fatal(err)
			}
			packet, ctx, _ := routingFlowPacket(t, obj)
			if protocol == unix.IPPROTO_UDP {
				_, packet, ctx, err = runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, make([]byte, 3520), make([]byte, 256))
				if err != nil {
					t.Fatal(err)
				}
			}
			installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: 2}})
			query := bpftestOutboundConnectivityQuery{Outbound: 2, L4proto: protocol, Ipversion: 4}
			if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{State: routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			for _, state := range []uint8{routingabi.DAEMON_ONLINE, routingabi.DAEMON_STOPPING} {
				if err := obj.ExitedMap.Update(uint32(0), state, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				want := uint32(math.MaxUint32)
				if state == routingabi.DAEMON_STOPPING {
					want = 2
					if protocol == unix.IPPROTO_TCP {
						packet[47] = 0x10
					}
				}
				got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
				if err != nil || got != want {
					t.Fatalf("state=%d verdict=%d want=%d: %v", state, got, want, err)
				}
			}
		})
	}
}

func TestReplacementPIDExemption(t *testing.T) {
	obj, err := loadTestObjects(t, "TestEntryMarkOther", "TestpktgenMacMatch")
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, _ := routingFlowPacket(t, obj)
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: 1}})
	for _, candidate := range []uint32{0, uint32(os.Getpid()) + 1, uint32(os.Getpid()) + 2, 0} {
		if err := obj.ReplacementPidMap.Update(uint32(0), candidate, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		want := uint32(2)
		if candidate == uint32(os.Getpid())+1 {
			want = math.MaxUint32
		}
		got, _, _, err := runBpfProgram(obj.TestEntryMarkOther, packet, ctx)
		if err != nil || got != want {
			t.Fatalf("candidate=%d verdict=%d want=%d: %v", candidate, got, want, err)
		}
	}
}

func TestReplacementPIDRevokedOnExit(t *testing.T) {
	parent := uint32(os.Getpid())
	candidate := parent + 1
	for _, test := range []struct {
		name       string
		registered uint32
		exiting    uint32
		want       uint32
	}{
		{"daemon", parent, parent, 0},
		{"candidate", parent, candidate, 0},
		{"unrelated", parent, parent + 2, candidate},
		{"recovered daemon", parent + 2, parent + 2, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			obj, err := loadTestObjects(t, "TestProcessExit")
			if err != nil {
				t.Fatal(err)
			}
			if err := obj.ReplacementPidMap.Update(uint32(0), candidate, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err := obj.DaemonIdentityMap.Update(uint32(0), uint64(test.registered), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 14)
			binary.NativeEndian.PutUint32(data, test.exiting)
			got, _, _, err := runBpfProgram(obj.TestProcessExit, data, nil)
			if err != nil || got != math.MaxUint32 {
				t.Fatalf("process exit verdict=%d: %v", got, err)
			}
			var exemption uint32
			if err := obj.ReplacementPidMap.Lookup(uint32(0), &exemption); err != nil || exemption != test.want {
				t.Fatalf("exemption=%d, want %d: %v", exemption, test.want, err)
			}
			var state uint8
			if err := obj.ExitedMap.Lookup(uint32(0), &state); err != nil || state != routingabi.DAEMON_STOPPING {
				t.Fatalf("exit weakened the replacement guard: state=%d, error=%v", state, err)
			}
		})
	}
}

func tcpSequence(packet []byte, seq, ack uint32) {
	binary.BigEndian.PutUint32(packet[38:42], seq)
	binary.BigEndian.PutUint32(packet[42:46], ack)
}

func tcpReply(packet []byte) []byte {
	reply := append([]byte(nil), packet...)
	copy(reply[26:30], packet[30:34])
	copy(reply[30:34], packet[26:30])
	copy(reply[34:36], packet[36:38])
	copy(reply[36:38], packet[34:36])
	return reply
}

func pinGuardTimers(t testing.TB, obj *bpftestObjects) {
	t.Helper()
	dir, err := os.MkdirTemp("/sys/fs/bpf", "dae-test-guard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for name, m := range map[string]*ebpf.Map{
		"state": obj.UdpConnStateMap,
		"route": obj.UdpRoutingCacheMap,
	} {
		if err := m.Pin(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoppingWithoutMapDescriptors(t *testing.T) {
	obj, err := loadTestObjects(t, "TproxyWanEgressL2", "TestpktgenMacMatch", "TestpktgenUdpRouteCacheMiss")
	if err != nil {
		t.Fatal(err)
	}
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: 0}})
	packet, ctx, _ := routingFlowPacket(t, obj)
	_, udp, udpCtx, err := runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, make([]byte, 3520), make([]byte, 256))
	if err != nil {
		t.Fatal(err)
	}
	if err := obj.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	// A persisted guard pins its timer maps, not just its program/link.
	pinGuardTimers(t, obj)
	if err := obj.bpftestMaps.Close(); err != nil {
		t.Fatal(err)
	}
	for _, flags := range []byte{0x02, 0x10, 0x14, 0x02, 0x10} {
		packet[47] = flags
		got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
		if err != nil || got != math.MaxUint32 {
			t.Fatalf("descriptor-free guard TCP flags=%#x verdict=%d: %v", flags, got, err)
		}
	}
	for range 2 {
		got, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, udp, udpCtx)
		if err != nil || got != math.MaxUint32 {
			t.Fatalf("descriptor-free guard UDP verdict=%d: %v", got, err)
		}
	}
}

func TestGuardTimerMapReferences(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(map[bool]string{false: "program-only", true: "pinned-timer-maps"}[pinned], func(t *testing.T) {
			obj, err := loadTestObjects(t, "TestGuardUdpTimers")
			if err != nil {
				t.Fatal(err)
			}
			if pinned {
				pinGuardTimers(t, obj)
			}
			got, _, _, err := runBpfProgram(obj.TestGuardUdpTimers, make([]byte, 64), make([]byte, 256))
			if err != nil || got != tcxNext {
				t.Fatalf("timer setup: verdict=%d err=%v", got, err)
			}
			type timerMap struct {
				id    ebpf.MapID
				key   any
				value any
			}
			var timers []timerMap
			for _, entry := range []struct {
				m     *ebpf.Map
				key   any
				value any
			}{
				{obj.UdpConnStateMap, bpftestTuplesKey{L4proto: unix.IPPROTO_UDP}, new(bpftestUdpConnState)},
				{obj.UdpRoutingCacheMap, bpftestUdpRoutingCacheKey{}, new(bpftestUdpRoutingCacheValue)},
			} {
				info, err := entry.m.Info()
				if err != nil {
					t.Fatal(err)
				}
				id, ok := info.ID()
				if !ok {
					t.Fatal("map ID unavailable")
				}
				timers = append(timers, timerMap{id, entry.key, entry.value})
			}
			if err := obj.bpftestMaps.Close(); err != nil {
				t.Fatal(err)
			}
			// Reopening before expiry restores usercnt and invalidates this test.
			time.Sleep(250 * time.Millisecond)
			for _, timer := range timers {
				m, err := ebpf.NewMapFromID(timer.id)
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				err = m.Lookup(timer.key, timer.value)
				if pinned && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("pinned timer did not reclaim flow: %v", err)
				}
				if !pinned && err != nil {
					t.Fatalf("program-only reference unexpectedly retained timer: %v", err)
				}
			}
		})
	}
}
