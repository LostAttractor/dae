/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"

	"github.com/daeuniverse/dae/component/network"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type RoutingMatcherBuilder struct {
	*routingState
	outboundName2Id      map[string]uint8
	ifmgr                *network.InterfaceManager
	destination          DestinationProgram
	flow                 FlowProgram
	domainSetIDs         map[string]uint32
	staticLpmIDs         map[string]int
	simulatedDomainSet   []routing.DomainSet
	rulesBuilder         *routing.RulesBuilder
	defaultProfileID     uint32
	profiles             []routingProfile
	fallbackSpans        map[bpfMatchSet]routingSpan
	interfaceRulePatches []routingInterfaceRulePatch
	ruleMetadata         map[uint32]routingRuleMetadata
	matchMetadata        map[uint32]routingMatchMetadata
	inactiveRules        []routingRuleMetadata
}

func newRoutingMatcherBuilder(outboundName2Id map[string]uint8, bpf *BPFState, ifmgr *network.InterfaceManager) *RoutingMatcherBuilder {
	b := &RoutingMatcherBuilder{
		routingState:    &routingState{bpf: bpf, clientSetSlots: make(map[string]int)},
		outboundName2Id: outboundName2Id,
		ifmgr:           ifmgr,
		domainSetIDs:    make(map[string]uint32),
		staticLpmIDs:    make(map[string]int),
		fallbackSpans:   make(map[bpfMatchSet]routingSpan),
	}
	rulesBuilder := routing.NewRulesBuilder()
	rulesBuilder.RegisterFunctionParser(consts.Function_Domain, routing.PlainParserFactory(b.addDomain))
	rulesBuilder.RegisterFunctionParser(consts.Function_DestIp, routing.IpParserFactory(b.addIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourceIp, routing.IpParserFactory(b.addSourceIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_DestPort, routing.PortRangeParserFactory(b.addPort))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourcePort, routing.PortRangeParserFactory(b.addSourcePort))
	rulesBuilder.RegisterFunctionParser(consts.Function_L4Proto, routing.L4ProtoParserFactory(b.addL4Proto))
	rulesBuilder.RegisterFunctionParser(consts.Function_Mac, routing.MacParserFactory(b.addSourceMac))
	rulesBuilder.RegisterFunctionParser(consts.Function_Client, routing.EmptyKeyPlainParserFactory(b.addClient))
	rulesBuilder.RegisterFunctionParser(consts.Function_ProcessName, routing.ProcessNameParserFactory(b.addProcessName))
	rulesBuilder.RegisterFunctionParser(consts.Function_Interface, routing.EmptyKeyPlainParserFactory(b.addInterface))
	rulesBuilder.RegisterFunctionParser(consts.Function_Dscp, routing.UintParserFactory(b.addDscp))
	rulesBuilder.RegisterFunctionParser(consts.Function_IpVersion, routing.IpVersionParserFactory(b.addIpVersion))
	b.rulesBuilder = rulesBuilder
	return b
}

func (b *RoutingMatcherBuilder) validate() error {
	// The kernel routing_map is a fixed-size ARRAY and both the eBPF program
	// and the userspace matcher index match sets by position; overflowing it
	// must be a configuration error, not a runtime panic.
	if b.routing.end > consts.MaxMatchSetLen {
		return fmt.Errorf("too many routing match sets: %v > %v (MaxMatchSetLen); please reduce routing rules (e.g. merge domains into a routing.dls file)", b.routing.end, consts.MaxMatchSetLen)
	}
	if len(b.rules)-b.routing.end > consts.MaxMatchSetLen*2 {
		return fmt.Errorf("too many destination match sets: %d", len(b.rules)-b.routing.end)
	}
	interfaceCount := 0
	for _, profile := range b.profiles {
		interfaceCount += len(profile.InterfaceNames)
	}
	if interfaceCount > maxRoutingInterfaces {
		return fmt.Errorf("too many routing interface bindings: %d > %d", interfaceCount, maxRoutingInterfaces)
	}

	return encodeRoutingJumps(b.rules)
}

// criticalOutbounds marks groups referenced by any rule that remains active
// when the group is unavailable. Skip-only and unreferenced groups are not.
func (b *RoutingMatcherBuilder) criticalOutbounds(outboundCount int) []bool {
	critical := make([]bool, outboundCount)
	for _, rule := range b.rules[b.routing.start:b.routing.end] {
		if rule.Action != uint8(consts.MatchActionRoute) {
			continue
		}
		outboundID := int(rule.Outbound)
		if outboundID < int(consts.OutboundUserDefinedMin) || outboundID >= outboundCount || rule.Flags&matchFlagSkipNoalive != 0 {
			continue
		}
		critical[outboundID] = true
	}
	return critical
}

func (b *RoutingMatcherBuilder) addDomain(f *config_parser.Function, key string, values []string, outbound *routing.Outbound) (err error) {
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		return fmt.Errorf("addDomain: unsupported key: %v", key)
	}
	values = slices.Clone(values)
	slices.Sort(values)
	values = slices.Compact(values)
	signature := fmt.Sprintf("%q:%q", key, values)
	id, exists := b.domainSetIDs[signature]
	if !exists {
		id = uint32(len(b.simulatedDomainSet))
		if id >= uint32(consts.MaxMatchSetLen) {
			return fmt.Errorf("too many distinct domain predicates: limit %d", consts.MaxMatchSetLen)
		}
		b.domainSetIDs[signature] = id
		b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
			Key: consts.RoutingDomainKey(key), RuleIndex: int(id), Domains: values,
		})
	}
	var value [16]byte
	binary.LittleEndian.PutUint32(value[:], id)
	return b.addMatch(f, consts.MatchType_DomainSet, value, outbound)
}

func sourceMacPrefixes(macAddrs [][6]byte) []netip.Prefix {
	var addr16 [16]byte
	values := make([]netip.Prefix, 0, len(macAddrs))
	for _, mac := range macAddrs {
		copy(addr16[10:], mac[:])
		prefix := netip.PrefixFrom(netip.AddrFrom16(addr16), 128)
		values = append(values, prefix)
	}
	return values
}

// Static sets can be shared between source/destination/MAC predicates; dynamic
// client sets have dedicated slots so membership updates cannot alter constants.
func (b *RoutingMatcherBuilder) internLPM(values []netip.Prefix) int {
	values = slices.Clone(values)
	for i := range values {
		values[i] = values[i].Masked()
	}
	slices.SortFunc(values, func(a, z netip.Prefix) int { return a.Compare(z) })
	values = slices.Compact(values)
	key := fmt.Sprint(values)
	if id, ok := b.staticLpmIDs[key]; ok {
		return id
	}
	id := len(b.simulatedLpmTries)
	b.staticLpmIDs[key] = id
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	return id
}

func (b *RoutingMatcherBuilder) addSourceMac(f *config_parser.Function, macAddrs [][6]byte, outbound *routing.Outbound) error {
	lpmTrieIndex := b.internLPM(sourceMacPrefixes(macAddrs))
	return b.addMacMatch(f, lpmTrieIndex, outbound)
}

func (b *RoutingMatcherBuilder) addClient(f *config_parser.Function, names []string, outbound *routing.Outbound) error {
	name := names[0]
	if err := config.ValidateClientName(name); err != nil {
		return err
	}

	slot, exists := b.clientSetSlots[name]
	if !exists {
		slot = len(b.simulatedLpmTries)
		b.clientSetSlots[name] = slot
		b.simulatedLpmTries = append(b.simulatedLpmTries, nil)
	}
	return b.addMacMatch(f, slot, outbound)
}

func (b *RoutingMatcherBuilder) addMacMatch(f *config_parser.Function, lpmTrieIndex int, outbound *routing.Outbound) error {
	var value [16]byte
	binary.LittleEndian.PutUint32(value[:], uint32(lpmTrieIndex))
	return b.addMatch(f, consts.MatchType_Mac, value, outbound)
}

func (b *RoutingMatcherBuilder) addIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	lpmTrieIndex := b.internLPM(values)
	var value [16]byte
	binary.LittleEndian.PutUint32(value[:], uint32(lpmTrieIndex))
	return b.addMatch(f, consts.MatchType_IpSet, value, outbound)
}

func (b *RoutingMatcherBuilder) addPort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) (err error) {
	return b.addMatches(f, consts.MatchType_Port, values, outbound, encodePortRange)
}

func (b *RoutingMatcherBuilder) addSourceIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	lpmTrieIndex := b.internLPM(values)
	var value [16]byte
	binary.LittleEndian.PutUint32(value[:], uint32(lpmTrieIndex))
	return b.addMatch(f, consts.MatchType_SourceIpSet, value, outbound)
}

func (b *RoutingMatcherBuilder) addSourcePort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) (err error) {
	return b.addMatches(f, consts.MatchType_SourcePort, values, outbound, encodePortRange)
}

func encodePortRange(value [2]uint16) [16]byte {
	return _bpfPortRange{PortStart: value[0], PortEnd: value[1]}.Encode()
}

func (b *RoutingMatcherBuilder) addL4Proto(f *config_parser.Function, values consts.L4ProtoType, outbound *routing.Outbound) (err error) {
	return b.addMatch(f, consts.MatchType_L4Proto, [16]byte{byte(values)}, outbound)
}

func (b *RoutingMatcherBuilder) addIpVersion(f *config_parser.Function, values consts.IpVersionType, outbound *routing.Outbound) (err error) {
	return b.addMatch(f, consts.MatchType_IpVersion, [16]byte{byte(values)}, outbound)
}

func (b *RoutingMatcherBuilder) addProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, outbound *routing.Outbound) (err error) {
	return b.addMatches(f, consts.MatchType_ProcessName, values, outbound, func(value [consts.TaskCommLen]byte) (encoded [16]byte) {
		copy(encoded[:], value[:])
		return encoded
	})
}

func (b *RoutingMatcherBuilder) addInterface(f *config_parser.Function, values []string, outbound *routing.Outbound) (err error) {
	for _, value := range values {
		if err := config.ValidateRoutingInterfaceName(value); err != nil {
			return err
		}
	}
	start := len(b.rules)
	if err := b.addMatches(f, consts.MatchType_IfIndex, values, outbound, func(string) [16]byte { return [16]byte{} }); err != nil {
		return err
	}
	for i, value := range values {
		// Registration is deferred until BuildKernspace so validation cannot
		// mutate maps shared with the currently running control plane.
		b.interfaceRulePatches = append(b.interfaceRulePatches, routingInterfaceRulePatch{
			ifname: value, matchIndex: start + i,
		})
	}
	return nil
}

func (b *RoutingMatcherBuilder) addDscp(f *config_parser.Function, values []uint8, outbound *routing.Outbound) (err error) {
	return b.addMatches(f, consts.MatchType_Dscp, values, outbound, func(value uint8) [16]byte { return [16]byte{value} })
}

func (b *RoutingMatcherBuilder) parseFallback(fallback *config_parser.Function) (bpfMatchSet, error) {
	outbound, err := routing.ParseOutbound(fallback)
	if err != nil {
		return bpfMatchSet{}, err
	}
	return b.matchSet(consts.MatchType_Fallback, false, outbound)
}

func (b *RoutingMatcherBuilder) addFallback(fallback bpfMatchSet) (span routingSpan, err error) {
	if existing, ok := b.fallbackSpans[fallback]; ok {
		return existing, nil
	}
	if len(b.rules) >= consts.MaxMatchSetLen {
		return span, fmt.Errorf("too many physical routing match sets: fallback exceeds %d", consts.MaxMatchSetLen)
	}
	start := uint32(len(b.rules))
	b.rules = append(b.rules, fallback)
	b.rememberRule(start, &config_parser.RoutingRule{Outbound: config_parser.Function{Name: "fallback"}}, "fallback")
	span = routingSpan{Start: start, End: start + 1}
	b.fallbackSpans[fallback] = span
	return span, nil
}

// NewRoutingMatcherBuilder compiles an already prepared rule sequence as a
// single default policy. Control-plane preparation uses compileRouting to add
// named policies, interface bindings and shared feature fragments.
func NewRoutingMatcherBuilder(rules []*config_parser.RoutingRule, outbounds map[string]uint8, bpf *BPFState, fallback config.FunctionOrString, ifmgr *network.InterfaceManager, capture *routingCapture, destinations routing.DestinationRewrites) (*RoutingMatcherBuilder, error) {
	fallbackFunction, err := config.ParseFunctionOrString(fallback)
	if err != nil {
		return nil, err
	}
	statements := make([]config.RoutingStatement, 0, len(rules))
	for _, rule := range rules {
		statements = append(statements, config.RoutingStatement{Kind: config.RoutingStatementRule, Rule: rule})
	}
	prepared := preparedRules{
		routing: &config.Routing{Policies: []config.RoutingPolicy{{Statements: statements, Fallback: fallbackFunction}}},
		capture: capture, destinations: destinations,
	}
	return prepared.compileRouting(outbounds, bpf, ifmgr)
}
