/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"math/rand"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"golang.org/x/exp/slices"
)

func TestAhocorasickSlimtrie(t *testing.T) {
	simulatedDomainSet := []routing.DomainSet{
		{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 0, Domains: []string{"alibaba.com", "test-ipv6.com"}},
		{Key: consts.RoutingDomainKey_Full, RuleIndex: 1, Domains: []string{"a.adtng.com", "bankcomm.com"}},
		{Key: consts.RoutingDomainKey_Keyword, RuleIndex: 2, Domains: []string{"ads", "bank"}},
		{Key: consts.RoutingDomainKey_Regex, RuleIndex: 3, Domains: []string{`^img.*\.com$`, `^bank.*\.com(\.cn)?$`}},
	}
	bf := NewBruteforce(consts.MaxMatchSetLen)
	actrie := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		bf.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
		actrie.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err := bf.Build(); err != nil {
		t.Fatal(err)
	}
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		domain string
		bits   uint32
	}{
		{domain: "alibaba.com", bits: 1 << 0},
		{domain: "WWW.ALIBABA.COM.", bits: 1 << 0},
		{domain: "notalibaba.com"},
		{domain: "a.adtng.com", bits: 1 << 1},
		{domain: "x.a.adtng.com"},
		{domain: "ads.example", bits: 1 << 2},
		{domain: "bankcomm.com", bits: 1<<1 | 1<<2 | 1<<3},
		{domain: "img-cdn.com", bits: 1 << 3},
	} {
		t.Run(test.domain, func(t *testing.T) {
			got := actrie.MatchDomainBitmap(test.domain)
			want := make([]uint32, len(got))
			want[0] = test.bits
			if !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}

	rng := rand.New(rand.NewSource(200))
	for i := 0; i < 10000; i++ {
		sample := TestSample[rng.Intn(len(TestSample))]
		choice := rng.Intn(10)
		switch {
		case choice < 4:
			addN := rng.Intn(5)
			buf := make([]byte, addN)
			for i := range buf {
				buf[i] = 'a' + byte(rng.Intn('z'-'a'))
			}
			sample = string(buf) + "." + sample
		case choice >= 4 && choice < 6:
			k := rng.Intn(len(sample))
			sample = sample[k:]
		default:
		}
		want := bf.MatchDomainBitmap(sample)
		got := actrie.MatchDomainBitmap(sample)
		if !slices.Equal(got, want) {
			t.Fatal(i, sample, got, want)
		}
	}
}
