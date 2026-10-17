/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"
	"strconv"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/vishvananda/netlink"
)

type interfaceReg struct {
	ruleIndex     int
	interfaceName string
}

type RequestMatcherBuilder struct {
	matcherBuilder[DnsRequestOutboundIndex, atomic.Uint32]
	interfaceRegs []interfaceReg
	ifmgr         *network.InterfaceManager
}

func NewRequestMatcherBuilder(
	rules []*config_parser.RoutingRule,
	upstreamName2Id map[string]uint8,
	fallback config.FunctionOrString,
	ifmgr *network.InterfaceManager,
) (b *RequestMatcherBuilder, err error) {
	b = &RequestMatcherBuilder{upstreamName2Id: upstreamName2Id, ifmgr: ifmgr}
	b.resolve = b.upstreamToId
	b.stage = "request"
	rulesBuilder := routing.NewRulesBuilder()
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	rulesBuilder.RegisterFunctionParser(consts.Function_DestIp, routing.IpParserFactory(b.addDestIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourceIp, routing.IpParserFactory(b.addSip))
	rulesBuilder.RegisterFunctionParser(consts.Function_Interface, routing.EmptyKeyPlainParserFactory(b.addInterface))
	if err = b.applyRules(rulesBuilder, rules, fallback); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *RequestMatcherBuilder) upstreamToId(upstream string) (upstreamId DnsRequestOutboundIndex, err error) {
	switch upstream {
	case DnsRequestOutboundIndex_Reject.String():
		upstreamId = DnsRequestOutboundIndex_Reject
	case DnsRequestOutboundIndex_AsIs.String():
		upstreamId = DnsRequestOutboundIndex_AsIs
	case DnsRequestOutboundIndex_LogicalAnd.String():
		upstreamId = DnsRequestOutboundIndex_LogicalAnd
	case DnsRequestOutboundIndex_LogicalOr.String():
		upstreamId = DnsRequestOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in section \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = DnsRequestOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func (b *RequestMatcherBuilder) addDestIp(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	return b.addIpSet(f, cidrs, upstream, consts.MatchType_IpSet)
}

func (b *RequestMatcherBuilder) addSip(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	return b.addIpSet(f, cidrs, upstream, consts.MatchType_SourceIpSet)
}

func (b *RequestMatcherBuilder) addInterface(f *config_parser.Function, values []string, upstream *routing.Outbound) (err error) {
	return upstream.ForEachLogicalOr(values, b.upstreamToId, func(value string, upstreamId DnsRequestOutboundIndex) error {
		b.interfaceRegs = append(b.interfaceRegs, interfaceReg{
			ruleIndex:     len(b.rules),
			interfaceName: value,
		})
		b.rules = append(b.rules, requestMatchSet{
			Type:     consts.MatchType_IfIndex,
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
		return nil
	})
}

func (b *RequestMatcherBuilder) Build() (*RequestMatcher, error) {
	compiled, err := b.build()
	if err != nil {
		return nil, err
	}
	m := RequestMatcher{matcher: compiled}
	if b.ifmgr != nil {
		for _, reg := range b.interfaceRegs {
			matchSet := &m.matches[reg.ruleIndex]
			initIndex := func(link netlink.Link) error {
				matchSet.Ifindex.Store(uint32(link.Attrs().Index))
				return nil
			}
			updateIndex := func(link netlink.Link) { matchSet.Ifindex.Store(uint32(link.Attrs().Index)) }
			resetIndex := func(netlink.Link) { matchSet.Ifindex.Store(0) }
			if err := b.ifmgr.RegisterSync(reg.interfaceName, initIndex, updateIndex, resetIndex); err != nil {
				return nil, fmt.Errorf("initialize request interface %q: %w", reg.interfaceName, err)
			}
		}
	}

	return &m, nil
}

type RequestMatcher struct {
	matcher[atomic.Uint32]
}

type requestMatchSet = matchRule[atomic.Uint32]

func addrToBin128(addr netip.Addr) string {
	return trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(addr.As16()), 128))
}

func (m *RequestMatcher) Match(
	qName string,
	qType uint16,
	ifindex uint32,
	dip netip.Addr,
	sip netip.Addr,
) (upstreamIndex DnsRequestOutboundIndex, err error) {
	var domainMatchBitmap []uint32
	if qName != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(qName)
	}

	if !dip.IsValid() || !sip.IsValid() {
		panic(fmt.Errorf("invalid dip or sip: dip=%v, sip=%v", dip, sip))
	}
	dipBin := addrToBin128(dip)
	sipBin := addrToBin128(sip)

	selected, err := m.matches.match(uint8(DnsRequestOutboundIndex_LogicalOr), uint8(DnsRequestOutboundIndex_LogicalMask), func(i int) (bool, error) {
		return m.matchValue(i, qType, ifindex, dipBin, sipBin, domainMatchBitmap)
	})
	return DnsRequestOutboundIndex(selected), err
}
