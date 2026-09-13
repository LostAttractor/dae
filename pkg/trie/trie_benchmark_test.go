// SPDX-License-Identifier: AGPL-3.0-only

package trie

import (
	"fmt"
	"net/netip"
	"testing"
)

// Fixed 128-bit queries mix hits and misses, including IPv4's mapped prefix.
// Construction and query conversion are excluded from the timed lookup.
func BenchmarkTrieHasPrefix(b *testing.B) {
	for _, v6 := range []bool{false, true} {
		for _, n := range []int{1, 256, 8192} {
			b.Run(fmt.Sprintf("v6=%t/prefixes=%d", v6, n), func(b *testing.B) {
				prefixes := make([]netip.Prefix, n)
				words := make([]string, n*2)
				for i := range n {
					addr := netip.AddrFrom4([4]byte{198, byte(i >> 8), byte(i), 0})
					miss := netip.AddrFrom4([4]byte{199, byte(i >> 8), byte(i), 1})
					mask := 24
					if v6 {
						addr = netip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 8: byte(i >> 8), 9: byte(i)})
						miss = netip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 8: byte(i >> 8), 9: byte(i), 10: 1})
						mask = 112
					}
					prefixes[i] = netip.PrefixFrom(addr, mask)
					words[2*i] = Prefix2bin128(netip.PrefixFrom(addr.Next(), addr.BitLen()))
					words[2*i+1] = Prefix2bin128(netip.PrefixFrom(miss, miss.BitLen()))
				}
				ss, err := NewTrieFromPrefixes(prefixes)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				i := 0
				for b.Loop() {
					if got := ss.HasPrefix(words[i%(2*n)]); got != (i%2 == 0) {
						b.Fatal("incorrect prefix result")
					}
					i++
				}
			})
		}
	}
}
