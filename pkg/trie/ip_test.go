// SPDX-License-Identifier: AGPL-3.0-only

package trie

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

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
