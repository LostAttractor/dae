/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func buildIPRequestMatcher(t *testing.T, functionName, value string) *RequestMatcher {
	t.Helper()

	builder, err := NewRequestMatcherBuilder(
		[]*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name:   functionName,
				Params: []*config_parser.Param{{Val: value}},
			}},
			Outbound: config_parser.Function{Name: "matched"},
		}},
		map[string]uint8{"matched": 1},
		consts.DnsRequestOutboundIndex_AsIs.String(),
		nil,
	)
	if err != nil {
		t.Fatalf("NewRequestMatcherBuilder: %v", err)
	}
	matcher, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return matcher
}

func matchRequest(t *testing.T, matcher *RequestMatcher, dip, sip string) consts.DnsRequestOutboundIndex {
	t.Helper()

	upstream, err := matcher.Match("", 0, 0, netip.MustParseAddr(dip), netip.MustParseAddr(sip))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return upstream
}

func TestRequestMatcherBareIPv6Address(t *testing.T) {
	tests := []struct {
		name         string
		functionName string
		matchingDip  string
		matchingSip  string
		differentDip string
		differentSip string
	}{
		{
			name:         "dip",
			functionName: consts.Function_DestIp,
			matchingDip:  "2001:db8::1",
			matchingSip:  "2001:db8:ffff::1",
			differentDip: "2001:db8::2",
			differentSip: "2001:db8:ffff::1",
		},
		{
			name:         "sip",
			functionName: consts.Function_SourceIp,
			matchingDip:  "2001:db8:ffff::1",
			matchingSip:  "2001:db8::1",
			differentDip: "2001:db8:ffff::1",
			differentSip: "2001:db8::2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := buildIPRequestMatcher(t, tt.functionName, "2001:db8::1")
			if got := matchRequest(t, matcher, tt.matchingDip, tt.matchingSip); got != 1 {
				t.Errorf("matching address selected upstream %v, want 1", got)
			}
			if got := matchRequest(t, matcher, tt.differentDip, tt.differentSip); got != consts.DnsRequestOutboundIndex_AsIs {
				t.Errorf("different host selected upstream %v, want %v", got, consts.DnsRequestOutboundIndex_AsIs)
			}
		})
	}
}

func TestRequestMatcherIPv6ZeroLengthPrefix(t *testing.T) {
	for _, functionName := range []string{consts.Function_DestIp, consts.Function_SourceIp} {
		t.Run(functionName, func(t *testing.T) {
			matcher := buildIPRequestMatcher(t, functionName, "::/0")
			if got := matchRequest(t, matcher, "2001:db8::1", "2001:db8:ffff::1"); got != 1 {
				t.Errorf("IPv6 address selected upstream %v, want 1", got)
			}
		})
	}
}

func TestRequestMatcherConcurrentIfindexUpdate(t *testing.T) {
	matcher := &RequestMatcher{
		matches: []requestMatchSet{
			{
				Type:     consts.MatchType_IfIndex,
				Upstream: uint8(consts.DnsRequestOutboundIndex_Reject),
			},
			{
				Type:     consts.MatchType_Fallback,
				Upstream: uint8(consts.DnsRequestOutboundIndex_AsIs),
			},
		},
	}

	const iterations = 10_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			matcher.matches[0].storeIfindex(uint32(i%2 + 1))
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			upstream, err := matcher.Match(
				"",
				0,
				1,
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("192.0.2.2"),
			)
			if err != nil {
				t.Errorf("Match: %v", err)
				return
			}
			if upstream != consts.DnsRequestOutboundIndex_Reject && upstream != consts.DnsRequestOutboundIndex_AsIs {
				t.Errorf("unexpected upstream %v", upstream)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
}
