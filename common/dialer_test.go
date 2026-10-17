/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestNetworkIndexRoundTrip(t *testing.T) {
	tests := []struct {
		index NetworkIndex
		name  string
	}{
		{NetworkTCP4, "tcp4"},
		{NetworkTCP6, "tcp6"},
		{NetworkUDP4, "udp4"},
		{NetworkUDP6, "udp6"},
	}
	if len(tests) != NetworkTypeCount {
		t.Fatalf("network count = %d, want %d", len(tests), NetworkTypeCount)
	}
	for _, test := range tests {
		if !test.index.Valid() {
			t.Errorf("network index %d is invalid", test.index)
		}
		if got := test.index.String(); got != test.name {
			t.Errorf("network %d = %q, want %q", test.index, got, test.name)
		}
		if got := test.index.NetworkType().Index(); got != test.index {
			t.Errorf("network %d round trip = %d", test.index, got)
		}
	}
	if NetworkInvalid.Valid() || NetworkIndex(NetworkTypeCount).Valid() {
		t.Fatal("out-of-range network index is valid")
	}
}

// Status arrays are indexed by common.NetworkIndex in the daemon and
// api.NetworkIndex in clients; both their order and their size are a contract.
func TestNetworkIndexAPIContract(t *testing.T) {
	if NetworkTypeCount != api.NetworkTypeCount {
		t.Fatalf("network count differs: %d vs %d", NetworkTypeCount, api.NetworkTypeCount)
	}
	for _, pair := range []struct {
		internal NetworkIndex
		wire     api.NetworkIndex
	}{
		{NetworkTCP4, api.NetworkTCP4}, {NetworkTCP6, api.NetworkTCP6},
		{NetworkUDP4, api.NetworkUDP4}, {NetworkUDP6, api.NetworkUDP6},
	} {
		if int(pair.internal) != int(pair.wire) || pair.internal.String() != pair.wire.String() {
			t.Fatalf("network mapping differs: %d/%s vs %d/%s", pair.internal, pair.internal, pair.wire, pair.wire)
		}
	}
}
