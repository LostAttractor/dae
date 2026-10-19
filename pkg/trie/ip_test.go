// SPDX-License-Identifier: AGPL-3.0-only

package trie

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestHasPrefixIPMappedBoundary(t *testing.T) {
	for _, networks := range [][]string{
		{"::/0"},
		{"0.0.0.0/0"},
		{"::/80"},
		{"::fffe:0:0/95"},
		{"::ffff:0:0/96"},
		{"::ffff:192.0.2.0/120"},
		{"192.0.2.0/24"},
		{"192.0.2.1/32"},
		{"2001:db8::/32"},
		{"::/128"},
		{"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"},
		{"::/80", "192.0.2.0/24", "2001:db8::/32"},
	} {
		t.Run(fmt.Sprint(networks), func(t *testing.T) {
			prefixes := make([]netip.Prefix, len(networks))
			for i, network := range networks {
				prefixes[i] = netip.MustParsePrefix(network)
			}
			trie, err := NewTrieFromPrefixes(prefixes)
			if err != nil {
				t.Fatal(err)
			}
			for _, ip := range []string{"0.0.0.0", "192.0.2.0", "192.0.2.1", "192.0.2.255", "198.51.100.1", "255.255.255.255", "::", "::1", "::fffe:c000:201", "::ffff:192.0.2.1", "2001:db8::1", "2001:db9::1"} {
				address := netip.MustParseAddr(ip)
				want := false
				for _, prefix := range prefixes {
					n := prefix.Bits()
					if prefix.Addr().Is4() {
						n += 96
					}
					want = want || netip.PrefixFrom(netip.AddrFrom16(prefix.Addr().As16()), n).Contains(netip.AddrFrom16(address.As16()))
				}
				if got := trie.HasPrefixIP(address.As16()); got != want {
					t.Errorf("address=%s: got %v, want %v", address, got, want)
				}
			}
		})
	}
}

// Mix hits and misses in both single-family and mixed-family sets.
func BenchmarkTrieIPLookup(b *testing.B) {
	for _, family := range []string{"ipv4", "ipv6", "mixed"} {
		for _, count := range []int{1, 256, 8192} {
			b.Run(fmt.Sprintf("%s/prefixes=%d", family, count), func(b *testing.B) {
				var prefixes []netip.Prefix
				var queries [][16]byte
				for i := range count {
					if family != "ipv6" {
						addr := netip.AddrFrom4([4]byte{198, byte(i >> 8), byte(i), 0})
						prefixes = append(prefixes, netip.PrefixFrom(addr, 24))
						queries = append(queries, addr.Next().As16(), netip.AddrFrom4([4]byte{199, byte(i >> 8), byte(i), 1}).As16())
					}
					if family != "ipv4" {
						addr := netip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 8: byte(i >> 8), 9: byte(i)})
						prefixes = append(prefixes, netip.PrefixFrom(addr, 112))
						queries = append(queries, addr.Next().As16(), [16]byte{0x20, 1, 0x0d, 0xb8, 8: byte(i >> 8), 9: byte(i), 10: 1})
					}
				}
				trie, err := NewTrieFromPrefixes(prefixes)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				i := 0
				for b.Loop() {
					if got := trie.HasPrefixIP(queries[i%len(queries)]); got != (i%2 == 0) {
						b.Fatal("incorrect prefix result")
					}
					i++
				}
			})
		}
	}
}

func TestHasPrefixIP(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for _, bits := range []int{0, 1, 31, 32, 63, 64, 95, 96, 97, 127, 128} {
		var prefixes []netip.Prefix
		var addresses []netip.Addr
		for range 32 {
			var raw [16]byte
			for i := range raw {
				raw[i] = byte(random.Uint32())
			}
			address := netip.AddrFrom16(raw)
			prefixes = append(prefixes, netip.PrefixFrom(address, bits))
			addresses = append(addresses, address, netip.AddrFrom4([4]byte{192, 0, 2, raw[15]}))
		}
		prefixes = append(prefixes, netip.MustParsePrefix("192.0.2.128/25"))
		trie, err := NewTrieFromPrefixes(prefixes)
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			want := false
			for _, prefix := range prefixes {
				// The routing ABI uses a single 128-bit address space.
				n := prefix.Bits()
				if prefix.Addr().Is4() {
					n += 96
				}
				want = want || netip.PrefixFrom(netip.AddrFrom16(prefix.Addr().As16()), n).Contains(netip.AddrFrom16(address.As16()))
			}
			if got := trie.HasPrefixIP(address.As16()); got != want {
				t.Fatalf("bits=%d address=%s: got %v, want %v", bits, address, got, want)
			}
		}
	}
	var empty *Trie
	if empty.HasPrefixIP([16]byte{}) {
		t.Fatal("nil trie matched")
	}
}

func BenchmarkTrieIP(b *testing.B) {
	trie, err := NewTrieFromPrefixes([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")})
	if err != nil {
		b.Fatal(err)
	}
	address := netip.MustParseAddr("192.0.2.123")
	b.Run("string", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !trie.HasPrefix(Prefix2bin128(netip.PrefixFrom(address, 32))) {
				b.Fatal("missing prefix")
			}
		}
	})
	b.Run("address", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !trie.HasPrefixIP(address.As16()) {
				b.Fatal("missing prefix")
			}
		}
	})
}
