/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trie

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestSelectIthOneAgainstBitScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(25, 180))
	for trial := range 128 {
		bitmap := make([]uint64, 64)
		for i := range bitmap {
			switch trial % 4 {
			case 0:
				bitmap[i] = rng.Uint64()
			case 1:
				bitmap[i] = ^uint64(0)
			case 2:
				bitmap[i] = uint64(1) << uint(i%64)
			case 3:
				if i%7 == 0 {
					bitmap[i] = rng.Uint64()
				}
			}
		}
		ss := &Trie{labelBitmap: bitmap}
		ss.init()
		index := 0
		for pos := range len(bitmap) * 64 {
			if bitmap[pos/64]&(uint64(1)<<uint(pos%64)) == 0 {
				continue
			}
			if got := selectIthOne(bitmap, ss.ranksBL, ss.selectsBL, index); got != pos {
				t.Fatalf("trial %d, one %d: got %d, want %d", trial, index, got, pos)
			}
			index++
		}
	}
}

func TestTriePrefixesAgainstContains(t *testing.T) {
	rng := rand.New(rand.NewPCG(128, 64))
	for _, v6 := range []bool{false, true} {
		address := func() netip.Addr {
			var bytes [16]byte
			for i := range bytes {
				bytes[i] = byte(rng.Uint32())
			}
			if v6 {
				return netip.AddrFrom16(bytes)
			}
			return netip.AddrFrom4([4]byte(bytes[:4]))
		}
		prefixes := make([]netip.Prefix, 128)
		for i := range prefixes {
			ip := address()
			prefixes[i] = netip.PrefixFrom(ip, 8+rng.IntN(ip.BitLen()-7)).Masked()
		}
		ss, err := NewTrieFromPrefixes(prefixes)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 1024 {
			ip := address()
			if i < len(prefixes) {
				ip = prefixes[i].Addr()
			}
			want := false
			for _, prefix := range prefixes {
				want = want || prefix.Contains(ip)
			}
			if got := ss.HasPrefix(Prefix2bin128(netip.PrefixFrom(ip, ip.BitLen()))); got != want {
				t.Fatalf("address %v: got %v, want %v", ip, got, want)
			}
		}
	}
}

func TestTrie(t *testing.T) {
	trie, err := NewTrie([]string{
		"moc.cbatnetnoc.",
		"moc.cbatnetnoc^",
		"nc.",
		"ua.moc.cbci.",
		"ua.moc.cbci^",
		"ua.moc.duolcababila.",
		"ua.moc.duolcababila^",
		"udiab.",
		"udiab^",
		"ue.cbci.",
		"ue.cbci^",
		"uhos.",
		"uhos^",
		"ul.cbci.",
		"ul.cbci^",
		"ur.dj.",
		"ur.dj^",
		"ur.llamt.",
		"ur.llamt^",
		"ur.sserpxeila.",
		"ur.sserpxeila^",
		"ur.wocsomcbci.",
		"ur.wocsomcbci^",
		"vt.32b.",
		"vt.32b^",
		"vt.akoaix.",
		"vt.akoaix^",
		"vt.eesia.",
		"vt.eesia^",
		"vt.eiq.",
		"vt.eiq^",
		"vt.gca.",
		"vt.gca^",
		"vt.ilibilib.",
		"vt.ilibilib^",
		"vt.iqnahz.",
		"vt.iqnahz^",
		"vt.ixiy.",
		"vt.ixiy^",
		"vt.low.",
		"vt.low^",
		"vt.nc361.",
		"vt.nc361^",
		"vt.obihzgnahs.",
		"vt.obihzgnahs^",
		"vt.ogmi.",
		"vt.ogmi^",
		"vt.spp.",
		"vt.spp^",
		"vt.uohsuhc.",
		"vt.uohsuhc^",
		"vt.uyuod.",
		"vt.uyuod^",
		"vt.vtig.",
		"vt.vtig^",
		"vt.vtnh.",
		"vt.vtnh^",
		"vt.zcbj.",
		"vt.zcbj^",
		"wk.moc.cbci.",
		"wk.moc.cbci^",
		"wt.moc.duolcababila.",
		"wt.moc.duolcababila^",
		"wt.moc.levarthh.",
		"wt.moc.levarthh^",
		"xc.f.",
		"xc.f^",
		"xm.moc.cbci.",
		"xm.moc.cbci^",
		"yapila.",
		"yapila^",
		"yl.lacisum.",
		"yl.lacisum^",
		"ym.moc.duolcababila.",
		"ym.moc.duolcababila^",
		"ym.pirtc.",
		"ym.pirtc^",
		"zib.anihcbmc.",
		"zib.anihcbmc^",
		"zib.duolcsndz.",
		"zib.duolcsndz^",
		"zib.fmc.",
		"zib.fmc^",
		"zk.ytamlacbci.",
		"zk.ytamlacbci^",
		"nc.ude.ctsu.srorrim.pct_.sptth_", // https://github.com/daeuniverse/daed/issues/400
	}, NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_")))
	if err != nil {
		t.Fatal(err)
	}
	if !(trie.HasPrefix("nc.tset^") == true) {
		t.Fatal("^test.cn")
	}
	if !(trie.HasPrefix("nc^") == false) {
		t.Fatal("^cn")
	}
	if !(trie.HasPrefix("nc.") == true) {
		t.Fatal(".cn")
	}
	if !(trie.HasPrefix("nc.^") == true) {
		t.Fatal("^.cn")
	}
	if !(trie.HasPrefix("nc._") == true) {
		t.Fatal("_.cn")
	}
	if !(trie.HasPrefix("n") == false) {
		t.Fatal("n")
	}
	if !(trie.HasPrefix("n^") == false) {
		t.Fatal("^n")
	}
	if !(trie.HasPrefix("moc.cbatnetnoc^") == true) {
		t.Fatal("contentabc.com")
	}
}

func TestIPv6ZeroLengthPrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("::/0")
	if got := Prefix2bin128(prefix); got != "" {
		t.Fatalf("Prefix2bin128(%v) = %q, want empty string", prefix, got)
	}

	trie, err := NewTrieFromPrefixes([]netip.Prefix{prefix})
	if err != nil {
		t.Fatalf("NewTrieFromPrefixes: %v", err)
	}
	for _, value := range []string{"::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		addr := netip.MustParseAddr(value)
		key := Prefix2bin128(netip.PrefixFrom(addr, addr.BitLen()))
		if !trie.HasPrefix(key) {
			t.Errorf("trie does not match IPv6 address %v", addr)
		}
	}
}
