/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type ResponseMatcherBuilder struct {
	matcherBuilder[DnsResponseOutboundIndex, struct{}]
}

func NewResponseMatcherBuilder(rules []*config_parser.RoutingRule, upstreamName2Id map[string]uint8, fallback config.FunctionOrString) (b *ResponseMatcherBuilder, err error) {
	b = &ResponseMatcherBuilder{upstreamName2Id: upstreamName2Id}
	b.resolve = b.upstreamToId
	b.stage = "response"
	rulesBuilder := routing.NewRulesBuilder()
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	rulesBuilder.RegisterFunctionParser(consts.Function_ResponseIp, routing.IpParserFactory(b.addIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_Upstream, routing.EmptyKeyPlainParserFactory(b.addUpstream))
	if err = b.applyRules(rulesBuilder, rules, fallback); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *ResponseMatcherBuilder) upstreamToId(upstream string) (upstreamId DnsResponseOutboundIndex, err error) {
	switch upstream {
	case DnsResponseOutboundIndex_Accept.String():
		upstreamId = DnsResponseOutboundIndex_Accept
	case DnsResponseOutboundIndex_Reject.String():
		upstreamId = DnsResponseOutboundIndex_Reject
	case DnsResponseOutboundIndex_LogicalAnd.String():
		upstreamId = DnsResponseOutboundIndex_LogicalAnd
	case DnsResponseOutboundIndex_LogicalOr.String():
		upstreamId = DnsResponseOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = DnsResponseOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func (b *ResponseMatcherBuilder) addIp(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) error {
	return b.addIpSet(f, cidrs, upstream, consts.MatchType_IpSet)
}

func (b *ResponseMatcherBuilder) addUpstream(f *config_parser.Function, values []string, upstream *routing.Outbound) (err error) {
	return upstream.ForEachLogicalOr(values, b.upstreamToId, func(value string, upstreamId DnsResponseOutboundIndex) error {
		lastUpstreamId, err := b.upstreamToId(value)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, responseMatchSet{
			Type:     consts.MatchType_Upstream,
			Value:    uint16(lastUpstreamId),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
		return nil
	})
}

func (b *ResponseMatcherBuilder) Build() (*ResponseMatcher, error) {
	compiled, err := b.build()
	if err != nil {
		return nil, err
	}
	m := ResponseMatcher{matcher: compiled}

	return &m, nil
}

type ResponseMatcher struct {
	matcher[struct{}]
}

type responseMatchSet = matchRule[struct{}]

func (m *ResponseMatcher) Match(
	qName string,
	qType uint16,
	ips []netip.Addr,
	upstream DnsRequestOutboundIndex,
) (upstreamIndex DnsResponseOutboundIndex, err error) {
	if qName == "" {
		return 0, fmt.Errorf("qName cannot be empty")
	}
	domainMatchBitmap := m.domainMatcher.MatchDomainBitmap(qName)
	bin128 := make([]string, 0, len(ips))
	for _, ip := range ips {
		bin128 = append(bin128, addrToBin128(ip))
	}

	selected, err := m.matches.match(uint8(DnsResponseOutboundIndex_LogicalOr), uint8(DnsResponseOutboundIndex_LogicalMask), func(i int) (bool, error) {
		return m.matchValue(i, qType, upstream, bin128, domainMatchBitmap)
	})
	return DnsResponseOutboundIndex(selected), err
}
