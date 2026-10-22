//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/internal/routingabi"
)

// tcp_flow_state.owner of a userspace relay.
const tcpFlowProxy = routingabi.FALLBACK_TOKEN_RESERVED

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
	if mark == 0 {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("plain direct retained state: %+v, %v", flow, err)
		}
	} else if err != nil || flow.Owner != 0 || flow.Mark != mark {
		t.Fatalf("direct flow lost mark: %+v, %v; want %d", flow, err, mark)
	}
}
