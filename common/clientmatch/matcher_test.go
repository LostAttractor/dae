/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package clientmatch_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/clientmatch"
)

func TestMatcherDefault(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
	}{
		{name: "nil"},
		{name: "empty", entries: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := clientmatch.Parse(tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range []netip.Addr{{}, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
				if matcher.Match(source, [6]byte{}) {
					t.Errorf("empty configuration allowed source %v", source)
				}
			}
		})
	}
	var zero clientmatch.Matcher
	if zero.Match(netip.Addr{}, [6]byte{}) {
		t.Error("zero Matcher must deny a client with unknown identities")
	}
}

func TestMatcherAddressSelectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		entry  string
		source string
		want   bool
	}{
		{"IPv4 exact", "192.0.2.1", "192.0.2.1", true},
		{"IPv4 other address", "192.0.2.1", "192.0.2.2", false},
		{"IPv4 CIDR masks host bits", "192.0.2.129/24", "192.0.2.1", true},
		{"IPv4 CIDR excludes adjacent network", "192.0.2.129/24", "192.0.3.1", false},
		{"IPv4 CIDR inclusive last address", "192.0.2.0/24", "192.0.2.255", true},
		{"IPv6 exact normalized text", "2001:0DB8:0000::1", "2001:db8::1", true},
		{"eight colon groups parsed as IPv6 before MAC", "02:aa:bb:cc:dd:ee:ff:01", "2:aa:bb:cc:dd:ee:ff:1", true},
		{"IPv6 exact excludes neighbor", "2001:db8::1", "2001:db8::2", false},
		{"IPv6 network masks host bits", "2001:db8:1::ffff/48", "2001:db8:1:ffff::1", true},
		{"IPv6 network excludes neighbor", "2001:db8:1::ffff/48", "2001:db8:2::1", false},
		{"observed zone ignored", "fe80::1", "fe80::1%eth0", true},
		{"observed zone CIDR", "fe80::/64", "fe80::1234%eth1", true},
		{"mapped source matches IPv4 exact", "192.0.2.1", "::ffff:192.0.2.1", true},
		{"mapped exact matches native source", "::ffff:192.0.2.1", "192.0.2.1", true},
		{"mapped hex exact matches native source", "::ffff:c000:201", "192.0.2.1", true},
		{"mapped zoned source matches IPv4", "192.0.2.1", "::ffff:192.0.2.1%eth0", true},
		{"mapped source matches IPv4 network", "192.0.2.0/24", "::ffff:192.0.2.255", true},
		{"mapped prefix matches native source", "::ffff:192.0.2.129/120", "192.0.2.1", true},
		{"mapped prefix matches mapped source", "::ffff:192.0.2.129/120", "::ffff:192.0.2.255", true},
		{"mapped prefix excludes adjacent network", "::ffff:192.0.2.129/120", "192.0.3.1", false},
		{"mapped exact prefix", "::ffff:192.0.2.1/128", "192.0.2.1", true},
		{"mapped exact prefix excludes neighbor", "::ffff:192.0.2.1/128", "192.0.2.2", false},
		{"mapped family prefix", "::ffff:192.0.2.1/96", "203.0.113.1", true},
		{"mapped family prefix excludes IPv6", "::ffff:0:0/96", "2001:db8::1", false},
		{"IPv4 any", "0.0.0.0/0", "203.0.113.255", true},
		{"IPv4 any mapped source", "0.0.0.0/0", "::ffff:203.0.113.255", true},
		{"IPv4 any excludes IPv6", "0.0.0.0/0", "2001:db8::1", false},
		{"IPv6 any", "::/0", "2001:db8::1", true},
		{"IPv6 any excludes native IPv4", "::/0", "192.0.2.1", false},
		{"IPv6 any excludes mapped IPv4", "::/0", "::ffff:192.0.2.1", false},
		{"native broad IPv6 prefix", "::/80", "::1", true},
		{"native broad IPv6 prefix excludes mapped IPv4", "::/80", "::ffff:192.0.2.1", false},
		{"IPv4 compatible IPv6 is not mapped", "192.0.2.1", "::192.0.2.1", false},
		{"invalid source is unknown", "0.0.0.0/0", "", false},
		{"whitespace trimmed", " 192.0.2.1 \t", "192.0.2.1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := clientmatch.Parse([]string{tc.entry})
			if err != nil {
				t.Fatal(err)
			}
			var source netip.Addr
			if tc.source != "" {
				source = netip.MustParseAddr(tc.source)
			}
			if got := matcher.Match(source, [6]byte{}); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v for %q", tc.source, got, tc.want, tc.entry)
			}
		})
	}
}

func TestMatcherOrderedIdentities(t *testing.T) {
	known := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	other := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xff}
	for _, tc := range []struct {
		name    string
		entries []string
		source  string
		mac     [6]byte
		want    bool
	}{
		{"MAC exact", []string{"02:aa:bb:cc:dd:ee"}, "192.0.2.1", known, true},
		{"all with unknown identities", []string{"all"}, "", [6]byte{}, true},
		{"all IPv4", []string{"all"}, "192.0.2.1", known, true},
		{"all IPv6", []string{"all"}, "2001:db8::1", known, true},
		{"all denied", []string{"-all"}, "192.0.2.1", known, false},
		{"MAC exclusion before all", []string{"-02:aa:bb:cc:dd:ee", "all"}, "192.0.2.1", known, false},
		{"all after unmatched exclusion", []string{"-02:aa:bb:cc:dd:ee", "all"}, "192.0.2.1", other, true},
		{"all precedes MAC exclusion", []string{"all", "-02:aa:bb:cc:dd:ee"}, "192.0.2.1", known, true},
		{"allow precedes deny all", []string{"02:aa:bb:cc:dd:ee", "-all"}, "192.0.2.1", known, true},
		{"deny all precedes allow", []string{"-all", "02:aa:bb:cc:dd:ee"}, "192.0.2.1", known, false},
		{"IP exclusion before all", []string{"-192.0.2.0/24", "all"}, "192.0.2.1", known, false},
		{"MAC differs", []string{"02:aa:bb:cc:dd:ee"}, "192.0.2.1", other, false},
		{"MAC uppercase", []string{"02:AA:BB:CC:DD:EE"}, "192.0.2.1", known, true},
		{"MAC dash notation", []string{"02-aa-bb-cc-dd-ee"}, "192.0.2.1", known, true},
		{"MAC dot notation", []string{"02aa.bbcc.ddee"}, "192.0.2.1", known, true},
		{"MAC without known IP", []string{"02:aa:bb:cc:dd:ee"}, "", known, true},
		{"IP deny precedes MAC allow", []string{"-192.0.2.0/24", "02:aa:bb:cc:dd:ee"}, "192.0.2.1", known, false},
		{"MAC allow precedes IP deny", []string{"02:aa:bb:cc:dd:ee", "-192.0.2.0/24"}, "192.0.2.1", known, true},
		{"MAC deny precedes IP allow", []string{"-02:aa:bb:cc:dd:ee", "192.0.2.0/24"}, "192.0.2.1", known, false},
		{"IP allow precedes MAC deny", []string{"192.0.2.0/24", "-02:aa:bb:cc:dd:ee"}, "192.0.2.1", known, true},
		{"IP exclusion before broad allow", []string{" - 192.0.2.1 ", "0.0.0.0/0"}, "192.0.2.1", known, false},
		{"broad allow before exclusion", []string{"0.0.0.0/0", "-192.0.2.1"}, "192.0.2.1", known, true},
		{"IPv6 exclusion before allow", []string{"-2001:db8:1::/48", "2001:db8::/32"}, "2001:db8:1::1", known, false},
		{"unmatched exclusion does not imply allow", []string{"-192.0.2.1"}, "192.0.2.2", known, false},
		{"both family catchalls", []string{"0.0.0.0/0", "::/0"}, "2001:db8::1", known, true},
		{"unknown MAC does not match allow", []string{"00:00:00:00:00:00"}, "192.0.2.1", [6]byte{}, false},
		{"unknown MAC deny continues to IP", []string{"-00:00:00:00:00:00", "192.0.2.1"}, "192.0.2.1", [6]byte{}, true},
		{"unknown MAC permit continues to IP deny", []string{"00:00:00:00:00:00", "-192.0.2.1"}, "192.0.2.1", [6]byte{}, false},
		{"unknown MAC skips real MAC and uses IP", []string{"-02:aa:bb:cc:dd:ee", "192.0.2.1"}, "192.0.2.1", [6]byte{}, true},
		{"both identities unknown deny explicit list", []string{"0.0.0.0/0", "::/0", "02:aa:bb:cc:dd:ee"}, "", [6]byte{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := clientmatch.Parse(tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			var source netip.Addr
			if tc.source != "" {
				source = netip.MustParseAddr(tc.source)
			}
			if got := matcher.Match(source, tc.mac); got != tc.want {
				t.Errorf("Match(%v, %x) = %v, want %v for %v", source, tc.mac, got, tc.want, tc.entries)
			}
		})
	}
}

func TestParseRejectsInvalidEntries(t *testing.T) {
	for _, entry := range []string{
		"", " \t ", "-", "-  ", "--192.0.2.1",
		"192.0.2.1,192.0.2.2", "-192.0.2.1,192.0.2.2",
		"example.com", "256.0.0.1", "192.0.2.1:443", "[2001:db8::1]:443", "[2001:db8::1]",
		"fe80::1%eth0", "fe80::1%eth0/64", "192.0.2.1/33", "2001:db8::/129", "192.0.2.1/-1",
		"::ffff:192.0.2.1/95", "::ffff:192.0.2.1/0", "-::ffff:c000:201/80",
		"02:aa:bb:cc:dd", "02:aa:bb:cc:dd:gg",
		"02-aa-bb-cc-dd-ee-ff-01", "02aa.bbcc.ddee.ff01", "02:aa:bb:cc:dd:ee/24",
	} {
		t.Run(entry, func(t *testing.T) {
			_, err := clientmatch.Parse([]string{"192.0.2.1", entry})
			if err == nil {
				t.Fatalf("Parse accepted invalid entry %q", entry)
			}
			if !strings.Contains(err.Error(), "client selector 2") {
				t.Errorf("error lacks entry position: %v", err)
			}
		})
	}
}

func TestMatcherDoesNotRetainInputSlice(t *testing.T) {
	entries := []string{"192.0.2.1"}
	matcher, err := clientmatch.Parse(entries)
	if err != nil {
		t.Fatal(err)
	}
	entries[0] = "0.0.0.0/0"
	if matcher.Match(netip.MustParseAddr("192.0.2.2"), [6]byte{}) {
		t.Fatal("changing input entries changed an existing matcher")
	}
}
