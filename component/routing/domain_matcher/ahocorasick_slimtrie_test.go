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

var domainMatcherTestSamples = []string{
	"9game.cn",
	"aliapp.org",
	"alibaba-inc.com",
	"alibaba.com",
	"alibabacapital.com",
	"alibabacorp.com",
	"alibabadoctor.com",
	"alibabafuturehotel.com",
	"alibabagroup.com",
	"alibabaplanet.com",
	"alibabaued.com",
	"alibabausercontent.com",
	"alifanyi.com",
	"alihealth.com.cn",
	"alihealth.hk",
	"aliimg.com",
	"51y5.net",
	"a.adtng.com",
	"aaxads.com",
	"addthisedge.com",
	"adtrue.com",
	"ad-srv.net",
	"ad.api.moji.com",
	"ad.wang502.com",
	"adbutter.net",
	"ads.trafficjunky.net",
	"adtechus.com",
	"adxprtz.com",
	"cdn.advertserve.com",
	"cdn.banclip.com",
	"cfts1tifqr.com",
	"contentabc.com",
	"cretgate.com",
	"ero-advertising.com",
	"eroadvertising.com",
	"exoclick.com",
	"exosrv.com",
	"go2.global",
	"img-bss.csdn.net",
	"imglnkc.com",
	"imglnkd.com",
	"innovid.com",
	"ja2.gamersky.com",
	"jl3.yjaxa.top",
	"juicyads.com",
	"kepler-37b.com",
	"lqc006.com",
	"moat.com",
	"moatads.com",
	"realsrv.com",
	"s4yxaqyq95.com",
	"shhs-ydd8x2.yjrmss.cn",
	"static.javhd.com",
	"tm-banners.gamingadult.com",
	"trafficfactory.biz",
	"tsyndicate.com",
	"abchina.com",
	"bankcomm.com",
	"bankofbeijing.com.cn",
	"bosc.cn",
	"bsb.com.cn",
	"ccb.com",
	"cgbchina.com.cn",
	"cib.com.cn",
	"citibank.com.cn",
	"cmbc.com.cn",
	"hsbc.com.cn",
	"hxb.com.cn",
	"njcb.com.cn",
	"psbc.com",
	"spdb.com.cn",
	"whccb.com",
	"_https._tcp.mirrors.ustc.edu.cn",
	"ipv4.master.test-ipv6.com",
}

var domainMatcherTestSets = []routing.DomainSet{
	{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 0, Domains: []string{"alibaba.com", "test-ipv6.com"}},
	{Key: consts.RoutingDomainKey_Full, RuleIndex: 1, Domains: []string{"a.adtng.com", "bankcomm.com"}},
	{Key: consts.RoutingDomainKey_Keyword, RuleIndex: 2, Domains: []string{"ads", "bank"}},
	{Key: consts.RoutingDomainKey_Regex, RuleIndex: 3, Domains: []string{`^img.*\.com$`, `^bank.*\.com(\.cn)?$`}},
}

var domainMatcherTestCases = []struct {
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
}

func TestAhocorasickSlimtrie(t *testing.T) {
	bf := NewBruteforce(consts.MaxMatchSetLen)
	actrie := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range domainMatcherTestSets {
		bf.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
		actrie.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err := bf.Build(); err != nil {
		t.Fatal(err)
	}
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	for _, test := range domainMatcherTestCases {
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
		sample := domainMatcherTestSamples[rng.Intn(len(domainMatcherTestSamples))]
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
