//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func lookupHandoff(m *ebpf.Map, key any, result *bpftestRoutingResult) error {
	var handoff bpftestRoutingHandoff
	err := m.Lookup(key, &handoff)
	*result = handoff.Result
	return err
}

func assertDirectTCPFlow(t *testing.T, obj *bpftestObjects, key bpftestTuplesKey, mark uint32) {
	t.Helper()
	var handoff bpftestRoutingHandoff
	if err := obj.RoutingTuplesMap.Lookup(key, &handoff); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("kernel-direct TCP created handoff: %+v, %v", handoff, err)
	}
	var flow bpftestTcpFlowState
	err := obj.TcpFlowMap.Lookup(key, &flow)
	if err != nil || flow.Fallback != 0 || flow.Mark != mark {
		t.Fatalf("direct flow lost mark: %+v, %v; want %d", flow, err, mark)
	}
}

// Userspace re-evaluates pname() rules, so the handoff carries the local
// process name the kernel matched.
func TestHandoffCarriesLocalProcessName(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	process := bpftestMatchSet{Type: uint8(consts.MatchType_ProcessName), Action: uint8(consts.MatchActionRoute), Outbound: 2}
	copy(process.Value[:], "curl")
	installRoutingFlow(t, obj, []bpftestMatchSet{process, {Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)}})
	query := bpftestOutboundConnectivityQuery{Outbound: 2, Ipversion: 4, L4proto: unix.IPPROTO_TCP}
	if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	if status, _, _, err := runBpfProgram(obj.TestEntryPname, packet, ctx); err != nil || status != 7 {
		t.Fatalf("local process flow: status %d, error %v; want redirect", status, err)
	}
	var handoff bpftestRoutingHandoff
	if err := obj.RoutingTuplesMap.Lookup(key, &handoff); err != nil {
		t.Fatal(err)
	}
	if handoff.Result.Outbound != 2 || string(bytes.TrimRight(handoff.Pname[:], "\x00")) != "curl" {
		t.Fatalf("handoff = %+v, want outbound 2 from curl", handoff)
	}
}
