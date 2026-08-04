/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"net/netip"
	"testing"
)

func TestParsePrefixesBareAddresses(t *testing.T) {
	got, err := parsePrefixes([]string{"192.0.2.1", "2001:db8::1"})
	if err != nil {
		t.Fatalf("parsePrefixes: %v", err)
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}
	if len(got) != len(want) {
		t.Fatalf("len(parsePrefixes(...)) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix %d = %v, want %v", i, got[i], want[i])
		}
	}
}
