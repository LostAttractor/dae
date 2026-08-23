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
	"github.com/daeuniverse/dae/component"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/vishvananda/netlink"
)

type ifnameReg struct {
	ruleIndex int
	ifname    string
}

type RequestMatcherBuilder struct {
	upstreamName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	rules              []requestMatchSet
	ipSet              []*trie.Trie
	ifnameRegs         []ifnameReg
	ifmgr              *component.InterfaceManager
}

func NewRequestMatcherBuilder(
	rules []*config_parser.RoutingRule,
	upstreamName2Id map[string]uint8,
	fallback config.FunctionOrString,
	ifmgr *component.InterfaceManager,
) (b *RequestMatcherBuilder, err error) {
	b = &RequestMatcherBuilder{upstreamName2Id: upstreamName2Id, ifmgr: ifmgr}
	rulesBuilder := routing.NewRulesBuilder()
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	rulesBuilder.RegisterFunctionParser(consts.Function_DestIp, routing.IpParserFactory(b.addDestIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourceIp, routing.IpParserFactory(b.addSip))
	rulesBuilder.RegisterFunctionParser(consts.Function_IfIndex, routing.UintParserFactory(b.addIfindex))
	rulesBuilder.RegisterFunctionParser(consts.Function_IfName, routing.EmptyKeyPlainParserFactory(b.addIfname))
	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}

	if err = b.addFallback(fallback); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *RequestMatcherBuilder) upstreamToId(upstream string) (upstreamId consts.DnsRequestOutboundIndex, err error) {
	switch upstream {
	case consts.DnsRequestOutboundIndex_Reject.String():
		upstreamId = consts.DnsRequestOutboundIndex_Reject
	case consts.DnsRequestOutboundIndex_AsIs.String():
		upstreamId = consts.DnsRequestOutboundIndex_AsIs
	case consts.DnsRequestOutboundIndex_LogicalAnd.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalAnd
	case consts.DnsRequestOutboundIndex_LogicalOr.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in section \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = consts.DnsRequestOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func (b *RequestMatcherBuilder) addQName(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		return fmt.Errorf("addQName: unsupported key: %v", key)
	}
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.rules),
		Domains:   values,
	})
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_DomainSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) appendLogicalOrRules(count int, upstream *routing.Outbound, build func(i int, upstreamId uint8) requestMatchSet) (err error) {
	for i := 0; i < count; i++ {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == count-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, build(i, uint8(upstreamId)))
	}
	return nil
}

func (b *RequestMatcherBuilder) addQType(f *config_parser.Function, values []uint16, upstream *routing.Outbound) (err error) {
	return b.appendLogicalOrRules(len(values), upstream, func(i int, upstreamId uint8) requestMatchSet {
		return requestMatchSet{
			Type:     consts.MatchType_QType,
			Value:    uint16(values[i]),
			Not:      f.Not,
			Upstream: upstreamId,
		}
	})
}

func (b *RequestMatcherBuilder) addIpSet(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound, matchType consts.MatchType) (err error) {
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	t, err := trie.NewTrieFromPrefixes(cidrs)
	if err != nil {
		return err
	}
	b.ipSet = append(b.ipSet, t)
	b.rules = append(b.rules, requestMatchSet{
		Value:    uint16(len(b.ipSet) - 1),
		Type:     matchType,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) addDestIp(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	return b.addIpSet(f, cidrs, upstream, consts.MatchType_IpSet)
}

func (b *RequestMatcherBuilder) addSip(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	return b.addIpSet(f, cidrs, upstream, consts.MatchType_SourceIpSet)
}

func (b *RequestMatcherBuilder) addIfindex(f *config_parser.Function, values []uint32, upstream *routing.Outbound) (err error) {
	return b.appendLogicalOrRules(len(values), upstream, func(i int, upstreamId uint8) requestMatchSet {
		return requestMatchSet{
			Type:     consts.MatchType_IfIndex,
			Ifindex:  values[i],
			Not:      f.Not,
			Upstream: upstreamId,
		}
	})
}

func (b *RequestMatcherBuilder) addIfname(f *config_parser.Function, values []string, upstream *routing.Outbound) (err error) {
	return b.appendLogicalOrRules(len(values), upstream, func(i int, upstreamId uint8) requestMatchSet {
		b.ifnameRegs = append(b.ifnameRegs, ifnameReg{
			ruleIndex: len(b.rules),
			ifname:    values[i],
		})
		return requestMatchSet{
			Type:     consts.MatchType_IfIndex,
			Not:      f.Not,
			Upstream: upstreamId,
		}
	})
}

func (b *RequestMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	fallback, err := config.ParseFunctionOrString(fallbackOutbound)
	if err != nil {
		return fmt.Errorf("invalid DNS request fallback: %w", err)
	}
	upstream, err := routing.ParseOutbound(fallback)
	if err != nil {
		return err
	}
	if upstream.Must {
		return fmt.Errorf("unsupported param: must")
	}
	if upstream.Mark != 0 {
		return fmt.Errorf("unsupported param: mark")
	}
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) Build() (matcher *RequestMatcher, err error) {
	var m RequestMatcher
	// Build domainMatcher
	m.domainMatcher = domain_matcher.NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return nil, err
	}
	m.ipSet = b.ipSet

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != consts.MatchType_Fallback {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}
	m.matches = b.rules

	if b.ifmgr != nil {
		for _, reg := range b.ifnameRegs {
			matchSet := &m.matches[reg.ruleIndex]
			initIndex := func(link netlink.Link) error {
				matchSet.storeIfindex(uint32(link.Attrs().Index))
				return nil
			}
			updateIndex := func(link netlink.Link) { matchSet.storeIfindex(uint32(link.Attrs().Index)) }
			resetIndex := func(netlink.Link) { matchSet.storeIfindex(0) }
			if err := b.ifmgr.RegisterSync(reg.ifname, initIndex, updateIndex, resetIndex); err != nil {
				return nil, fmt.Errorf("initialize request interface %q: %w", reg.ifname, err)
			}
		}
	}

	return &m, nil
}

type RequestMatcher struct {
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.
	ipSet         []*trie.Trie

	matches []requestMatchSet
}

type requestMatchSet struct {
	Value    uint16
	Ifindex  uint32
	Not      bool
	Type     consts.MatchType
	Upstream uint8
}

func (m *requestMatchSet) loadIfindex() uint32 {
	return atomic.LoadUint32(&m.Ifindex)
}

func (m *requestMatchSet) storeIfindex(ifindex uint32) {
	atomic.StoreUint32(&m.Ifindex, ifindex)
}

func addrToBin128(addr netip.Addr) string {
	return trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(addr.As16()), 128))
}

func (m *RequestMatcher) Match(
	qName string,
	qType uint16,
	ifindex uint32,
	dip netip.Addr,
	sip netip.Addr,
) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	var domainMatchBitmap []uint32
	if qName != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(qName)
	}

	if !dip.IsValid() || !sip.IsValid() {
		panic(fmt.Errorf("invalid dip or sip: dip=%v, sip=%v", dip, sip))
	}
	dipBin := addrToBin128(dip)
	sipBin := addrToBin128(sip)

	goodSubrule := false
	badRule := false
	for i := range m.matches {
		match := &m.matches[i]
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch match.Type {
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			}
		case consts.MatchType_QType:
			if qType == match.Value {
				goodSubrule = true
			}
		case consts.MatchType_IpSet:
			if m.ipSet[match.Value].HasPrefix(dipBin) {
				goodSubrule = true
			}
		case consts.MatchType_SourceIpSet:
			if m.ipSet[match.Value].HasPrefix(sipBin) {
				goodSubrule = true
			}
		case consts.MatchType_IfIndex:
			if ifindex == match.loadIfindex() {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		upstream := consts.DnsRequestOutboundIndex(match.Upstream)
		if upstream != consts.DnsRequestOutboundIndex_LogicalOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if goodSubrule == match.Not {
				// This subrule does not hit.
				badRule = true
			}

			// Reset goodSubrule.
			goodSubrule = false
		}

		if upstream&consts.DnsRequestOutboundIndex_LogicalMask !=
			consts.DnsRequestOutboundIndex_LogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				return upstream, nil
			}
			badRule = false
		}
	}
	return 0, fmt.Errorf("no match set hit")
}
