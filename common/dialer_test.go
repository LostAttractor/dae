/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import "testing"

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
