/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestEncodeOutboundConnectivity(t *testing.T) {
	tests := []struct {
		name                   string
		alive                  bool
		noConnectivityTrySniff bool
		noConnectivityOutbound consts.OutboundIndex
		want                   uint32
	}{
		{
			name:                   "alive",
			alive:                  true,
			noConnectivityTrySniff: true,
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityAlive,
		},
		{
			name:                   "dead with try sniff",
			noConnectivityTrySniff: true,
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityNoAliveTrySniff,
		},
		{
			name:                   "dead fallback direct",
			noConnectivityOutbound: consts.OutboundDirect,
			want:                   outboundConnectivityNoAliveDirect,
		},
		{
			name:                   "dead fallback block",
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityNoAliveBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeOutboundConnectivity(tt.alive, tt.noConnectivityTrySniff, tt.noConnectivityOutbound)
			if got != tt.want {
				t.Fatalf("encodeOutboundConnectivity() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestOutboundRecoveryCallbackFiresOnGlobalRecovery(t *testing.T) {
	core := new(controlPlaneCore)
	var recoveries atomic.Int32
	core.setOutboundRecoveryCallback(func() { recoveries.Add(1) })
	network := 0
	first := uint8(consts.OutboundUserDefinedMin)
	second := first + 1

	if callback := core.recordOutboundConnectivity(first, network, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 1 {
		t.Fatalf("recoveries = %d, want 1", got)
	}
	if callback := core.recordOutboundConnectivity(second, network, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 1 {
		t.Fatalf("second live outbound triggered recovery: %d", got)
	}

	core.recordOutboundConnectivity(first, network, false)
	core.recordOutboundConnectivity(second, network, false)
	if callback := core.recordOutboundConnectivity(second, network, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 2 {
		t.Fatalf("second global recovery count = %d, want 2", got)
	}
}

func TestOutboundRecoveryIsTrackedPerNetwork(t *testing.T) {
	core := new(controlPlaneCore)
	var recoveries atomic.Int32
	core.setOutboundRecoveryCallback(func() { recoveries.Add(1) })
	outbound := uint8(consts.OutboundUserDefinedMin)

	if callback := core.recordOutboundConnectivity(outbound, 0, true); callback != nil {
		callback()
	}
	if callback := core.recordOutboundConnectivity(outbound, 1, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 2 {
		t.Fatalf("recoveries = %d, want one per network", got)
	}
}

func TestEncodeOutboundConnectivityRejectsInvalidFallback(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected invalid no-connectivity outbound to panic")
		}
	}()
	encodeOutboundConnectivity(false, false, consts.OutboundUserDefinedMin)
}
