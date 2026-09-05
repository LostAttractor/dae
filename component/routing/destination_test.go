// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDestinationRewrites(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.1")
	targets := []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8::1")}
	rules := DestinationRewrites{
		{From: source, To: targets},
		{From: source, To: []netip.Addr{netip.MustParseAddr("203.0.113.1")}, Proxy: true},
		{From: targets[0], To: []netip.Addr{netip.MustParseAddr("203.0.113.2")}},
	}
	got, ok := rules.Rewrite(netip.MustParseAddrPort("[::ffff:192.0.2.1]:8443"), false)
	if !ok || got.Port() != 8443 || !slices.Contains(targets, got.Addr()) {
		t.Fatalf("rewrite lost order or port: %s, %v", got, ok)
	}
	for _, address := range []string{"192.0.2.1:443", "192.0.2.99:443"} {
		dst := netip.MustParseAddrPort(address)
		if got, ok := rules.Rewrite(dst, true); ok || got != dst {
			t.Fatalf("proxy bypass fell through to a later rule: %s, %v", got, ok)
		}
	}
	rules[0].To = targets[:1]
	if got, _ := rules.Rewrite(netip.AddrPortFrom(source, 443), false); got.Addr() != targets[0] {
		t.Fatalf("rewrite recursed: %s", got)
	}
	rules[0].Proxy = true
	if _, ok := rules.Rewrite(netip.AddrPortFrom(source, 443), true); !ok {
		t.Fatal("explicit proxy rewrite was skipped")
	}
}
