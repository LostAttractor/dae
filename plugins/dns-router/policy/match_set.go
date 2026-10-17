// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
)

// Only request rules carry mutable interface indices. Response rules use an
// empty field, while both directions share compilation and boolean evaluation.
type matchRule[Ifindex any] struct {
	Value    uint16
	Ifindex  Ifindex
	Not      bool
	Type     consts.MatchType
	Upstream uint8
}

type matchSet[Ifindex any] []matchRule[Ifindex]

func (matches matchSet[Ifindex]) match(logicalOr, logicalMask uint8, value func(int) (bool, error)) (uint8, error) {
	goodSubrule, badRule := false, false
	for i := range matches {
		rule := &matches[i]
		if !badRule && !goodSubrule {
			var err error
			goodSubrule, err = value(i)
			if err != nil {
				return 0, err
			}
		}
		if rule.Upstream != logicalOr {
			if goodSubrule == rule.Not {
				badRule = true
			}
			goodSubrule = false
		}
		if rule.Upstream&logicalMask != logicalMask {
			if !badRule {
				return rule.Upstream, nil
			}
			badRule = false
		}
	}
	return 0, fmt.Errorf("no match set hit")
}

type matcher[Ifindex any] struct {
	domainMatcher routing.DomainMatcher
	ipSet         []*trie.Trie
	matches       matchSet[Ifindex]
	sources       map[int]*config_parser.RoutingRule
}

type matcherBuilder[Action ~int16 | ~uint8, Ifindex any] struct {
	upstreamName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	rules              matchSet[Ifindex]
	ipSet              []*trie.Trie
	sources            map[int]*config_parser.RoutingRule
	resolve            func(string) (Action, error)
	stage              string
}

func (b *matcherBuilder[Action, Ifindex]) applyRules(builder *routing.RulesBuilder, rules []*config_parser.RoutingRule, fallback config.FunctionOrString) error {
	b.sources = make(map[int]*config_parser.RoutingRule)
	for _, rule := range rules {
		b.sources[len(b.rules)] = rule
		if err := builder.Apply([]*config_parser.RoutingRule{rule}); err != nil {
			return err
		}
	}
	return b.addFallback(fallback)
}

func (b *matcherBuilder[Action, Ifindex]) addQName(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
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
	upstreamId, err := b.resolve(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, matchRule[Ifindex]{
		Type:     consts.MatchType_DomainSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *matcherBuilder[Action, Ifindex]) addQType(f *config_parser.Function, values []uint16, upstream *routing.Outbound) (err error) {
	return upstream.ForEachLogicalOr(values, b.resolve, func(value uint16, upstreamId Action) error {
		b.rules = append(b.rules, matchRule[Ifindex]{
			Type:     consts.MatchType_QType,
			Value:    value,
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
		return nil
	})
}

func (b *matcherBuilder[Action, Ifindex]) addIpSet(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound, matchType consts.MatchType) (err error) {
	upstreamId, err := b.resolve(upstream.Name)
	if err != nil {
		return err
	}
	t, err := trie.NewTrieFromPrefixes(cidrs)
	if err != nil {
		return err
	}
	b.ipSet = append(b.ipSet, t)
	b.rules = append(b.rules, matchRule[Ifindex]{
		Value:    uint16(len(b.ipSet) - 1),
		Type:     matchType,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *matcherBuilder[Action, Ifindex]) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	fallback, err := config.ParseFunctionOrString(fallbackOutbound)
	if err != nil {
		return fmt.Errorf("invalid DNS %s fallback: %w", b.stage, err)
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
	upstreamId, err := b.resolve(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, matchRule[Ifindex]{
		Type:     consts.MatchType_Fallback,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *matcherBuilder[Action, Ifindex]) build() (result matcher[Ifindex], err error) {
	var m matcher[Ifindex]
	// Build domainMatcher.
	m.domainMatcher = domain_matcher.NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return result, err
	}
	// IpSet.
	m.ipSet = b.ipSet

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != consts.MatchType_Fallback {
		return result, fmt.Errorf("fallback rule MUST be the last")
	}
	m.matches = b.rules
	m.sources = b.sources

	return m, nil
}
