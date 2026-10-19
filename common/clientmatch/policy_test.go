// SPDX-License-Identifier: AGPL-3.0-only

package clientmatch

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestCompiledPolicyPreservesOrderedSelectors(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	selectors := []string{"10.0.0.0/8", "-10.1.0.0/16", "10.1.2.0/24", "-02:00:00:00:00:01", "2001:db8::/32", "-2001:db8:1::/48", "all", "-all", "::/0", "0.0.0.0/0", "00:00:00:00:00:00"}
	ips := []string{"10.1.2.3", "10.4.3.2", "192.0.2.1", "::ffff:10.1.2.3", "2001:db8:1::1", "2001:db8:2::1", "2001:4860::1"}
	// Every ordered pair crosses broad/narrow, allow/deny, IP/MAC, family and
	// wildcard precedence without importing external fixtures.
	for _, a := range selectors {
		for _, b := range selectors {
			matcher, err := Parse([]string{a, b})
			if err != nil {
				t.Fatal(err)
			}
			policy := matcher.Compile(nil)
			for _, text := range ips {
				for _, observed := range [][6]byte{mac, {}, {2, 0, 0, 0, 0, 2}} {
					ip := netip.MustParseAddr(text)
					got, _ := policy.Match(ip, observed)
					if want := matcher.Match(ip, observed); got != want {
						t.Fatalf("%q %q source=%s mac=%x: %v, want %v", a, b, ip, observed, got, want)
					}
				}
			}
			for _, enabled := range []bool{false, true} {
				overrides := map[[6]byte]bool{mac: enabled}
				policy = matcher.Compile(overrides)
				overrides[mac] = !enabled
				source := netip.MustParseAddr("192.0.2.1")
				got, override := policy.Match(source, mac)
				if got != enabled || override == nil || *override != enabled {
					t.Fatalf("override did not precede %q %q", a, b)
				}
				// Clearing the override returns to the configured decision.
				if configured := policy.Default(source, mac); configured != matcher.Match(source, mac) {
					t.Fatalf("default for %q %q is %v, want the configured %v", a, b, configured, !configured)
				}
			}
		}
	}
}

func TestCompiledPrefixKeepsEarlierNarrowRule(t *testing.T) {
	entries := []string{"-10.1.2.0/24", "10.0.0.0/8", "-10.1.0.0/16", "10.1.2.3"}
	matcher, _ := Parse(entries)
	policy := matcher.Compile(nil)
	for i := range 256 {
		for _, text := range []string{fmt.Sprintf("10.1.2.%d", i), fmt.Sprintf("10.1.%d.1", i)} {
			ip := netip.MustParseAddr(text)
			if got, _ := policy.Match(ip, [6]byte{}); got != matcher.Match(ip, [6]byte{}) {
				t.Fatalf("ordered overlap mismatch for %s", ip)
			}
		}
	}
}
