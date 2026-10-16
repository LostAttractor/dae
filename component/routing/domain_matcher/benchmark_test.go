/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func BenchmarkAhocorasickSlimtrie(b *testing.B) {
	matcher := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range domainMatcherTestSets {
		matcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err := matcher.Build(); err != nil {
		b.Fatal(err)
	}
	for _, test := range domainMatcherTestCases {
		b.Run(test.domain, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got := matcher.MatchDomainBitmap(test.domain); got[0] != test.bits {
					b.Fatalf("got %v, want first word %d", got, test.bits)
				}
			}
		})
	}
}
