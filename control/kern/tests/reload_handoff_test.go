//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func TestReloadPendingSYNAndConsumedHandoff(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	capture := routingPortRule(443, consts.MatchActionCapture, 0)
	capture.Flags = 1 << 3
	installRoutingFlow(t, obj, []bpftestMatchSet{capture, {Type: 11, Outbound: 0}})
	syn, key := devicePacket(false, unix.IPPROTO_TCP, 2)
	ack, _ := devicePacket(false, unix.IPPROTO_TCP, 0x10)
	run := func(packet []byte, want uint32) {
		t.Helper()
		got, _, _, err := runBpfProgram(obj.LanIngressL2, packet, make([]byte, 256))
		if err != nil || got != want {
			t.Fatalf("TCP verdict=%d, %v; want %d", got, err, want)
		}
	}
	run(syn, 7)
	var original bpftestRoutingHandoff
	if err := obj.RoutingTuplesMap.Lookup(key, &original); err != nil {
		t.Fatal(err)
	}
	// Make deadline renewal observable without waiting for a clock tick.
	original.Expires -= 5
	if err := obj.RoutingTuplesMap.Update(key, original, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := obj.RoutingGeneration.Set(uint32(1)); err != nil {
		t.Fatal(err)
	}
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: 11, Outbound: 1}})
	run(syn, 7) // retransmission must stay with the old generation
	var retained bpftestRoutingHandoff
	if err := obj.RoutingTuplesMap.LookupAndDelete(key, &retained); err != nil {
		t.Fatal(err)
	}
	if retained != original {
		t.Fatal("SYN retry changed generation or extended the setup deadline")
	}
	run(ack, 7) // consuming setup must not remove established forwarding state
	syn[41]++
	run(syn, 2)
}

func TestReloadInvalidatesUnboundUDPCache(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: 11, Outbound: 0}})
	packet, _ := devicePacket(false, unix.IPPROTO_UDP, 0)
	run := func(want uint32) {
		got, _, _, err := runBpfProgram(obj.LanIngressL2, packet, make([]byte, 256))
		if err != nil || got != want {
			t.Fatalf("UDP verdict=%d, %v; want %d", got, err, want)
		}
	}
	run(^uint32(0))
	if err := obj.RoutingGeneration.Set(uint32(1)); err != nil {
		t.Fatal(err)
	}
	if err := obj.RoutingMap.Update(uint32(0), bpftestMatchSet{Type: 11, Outbound: 1}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	run(2)
}
