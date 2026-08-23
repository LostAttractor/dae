/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/dae/component"
	"github.com/daeuniverse/dae/pkg/trie"
	log "github.com/sirupsen/logrus"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/vishvananda/netlink"
)

type RoutingMatcherBuilder struct {
	outboundName2Id    map[string]uint8
	ifmgr              *component.InterfaceManager
	bpf                *bpfState
	rules              []bpfMatchSet
	rulesMu            sync.RWMutex
	simulatedLpmTries  [][]netip.Prefix
	simulatedDomainSet []routing.DomainSet
	fallback           *routing.Outbound

	// kernspaceBuilders collect side effects that must run against the
	// shared eBPF state (e.g. registering interface watchers that update
	// RoutingMap on link events). They are deferred until BuildKernspace so
	// that NewRoutingMatcherBuilder stays free of BPF map writes and can
	// run during the validation phase of a reload.
	kernspaceBuilders []func() error
}

func NewRoutingMatcherBuilder(rules []*config_parser.RoutingRule, outboundName2Id map[string]uint8, bpf *bpfState, fallback config.FunctionOrString, ifmgr *component.InterfaceManager) (b *RoutingMatcherBuilder, err error) {
	b = &RoutingMatcherBuilder{outboundName2Id: outboundName2Id, ifmgr: ifmgr, bpf: bpf}
	rulesBuilder := routing.NewRulesBuilder()
	rulesBuilder.RegisterFunctionParser(consts.Function_Domain, routing.PlainParserFactory(b.addDomain))
	rulesBuilder.RegisterFunctionParser(consts.Function_DestIp, routing.IpParserFactory(b.addIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourceIp, routing.IpParserFactory(b.addSourceIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_DestPort, routing.PortRangeParserFactory(b.addPort))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourcePort, routing.PortRangeParserFactory(b.addSourcePort))
	rulesBuilder.RegisterFunctionParser(consts.Function_L4Proto, routing.L4ProtoParserFactory(b.addL4Proto))
	rulesBuilder.RegisterFunctionParser(consts.Function_Mac, routing.MacParserFactory(b.addSourceMac))
	rulesBuilder.RegisterFunctionParser(consts.Function_ProcessName, routing.ProcessNameParserFactory(b.addProcessName))
	rulesBuilder.RegisterFunctionParser(consts.Function_IfIndex, routing.UintParserFactory(b.addIfIndex))
	rulesBuilder.RegisterFunctionParser(consts.Function_IfName, routing.EmptyKeyPlainParserFactory(b.addIfName))
	rulesBuilder.RegisterFunctionParser(consts.Function_Dscp, routing.UintParserFactory(b.addDscp))
	rulesBuilder.RegisterFunctionParser(consts.Function_IpVersion, routing.IpVersionParserFactory(b.addIpVersion))
	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}

	if err = b.addFallback(fallback); err != nil {
		return nil, err
	}

	// The kernel routing_map is a fixed-size ARRAY and both the eBPF program
	// and the userspace matcher index match sets by position; overflowing it
	// must be a configuration error, not a runtime panic.
	if len(b.rules) > consts.MaxMatchSetLen {
		return nil, fmt.Errorf("too many routing match sets: %v > %v (MaxMatchSetLen); please reduce routing rules (e.g. merge domains into a routing.dls file)", len(b.rules), consts.MaxMatchSetLen)
	}

	// Validate skip_while_noalive usage. The flag is carried by every match
	// set of a rule but only takes effect on the rule tail.
	for i := range b.rules {
		r := &b.rules[i]
		if !r.SkipWhileNoalive {
			continue
		}
		outbound := consts.OutboundIndex(r.Outbound)
		if outbound&consts.OutboundLogicalMask == consts.OutboundLogicalMask {
			// Intermediate match set of a subrule.
			continue
		}
		if r.Type == uint8(consts.MatchType_Fallback) {
			return nil, fmt.Errorf("skip_while_noalive cannot be used on fallback: skipping fallback leaves traffic unroutable")
		}
		if outbound == consts.OutboundDirect || outbound == consts.OutboundBlock {
			return nil, fmt.Errorf("skip_while_noalive cannot be used on outbound %v: built-in outbounds do not participate in connectivity checks", outbound.String())
		}
	}

	return b, nil
}

// criticalOutbounds marks groups referenced by any rule that remains active
// when the group is unavailable. Skip-only and unreferenced groups are not.
func (b *RoutingMatcherBuilder) criticalOutbounds(outboundCount int) []bool {
	critical := make([]bool, outboundCount)
	for _, rule := range b.rules {
		outboundID := int(rule.Outbound)
		if outboundID < int(consts.OutboundUserDefinedMin) || outboundID >= outboundCount || rule.SkipWhileNoalive {
			continue
		}
		critical[outboundID] = true
	}
	return critical
}

func (b *RoutingMatcherBuilder) outboundToId(outbound string) (uint8, error) {
	var outboundId uint8
	switch outbound {
	case consts.OutboundLogicalOr.String():
		outboundId = uint8(consts.OutboundLogicalOr)
	case consts.OutboundLogicalAnd.String():
		outboundId = uint8(consts.OutboundLogicalAnd)
	case consts.OutboundMustRules.String():
		outboundId = uint8(consts.OutboundMustRules)
	case consts.OutboundControlPlaneRouting.String():
		outboundId = uint8(consts.OutboundControlPlaneRouting)
	default:
		var ok bool
		outboundId, ok = b.outboundName2Id[outbound]
		if !ok {
			return 0, fmt.Errorf("outbound (group) %v not found; please define it in section \"group\"", strconv.Quote(outbound))
		}
	}
	return outboundId, nil
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
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.rules),
		Domains:   values,
	})
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, bpfMatchSet{
		Type:             uint8(consts.MatchType_DomainSet),
		Not:              f.Not,
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	})
	return nil
}

func (b *RoutingMatcherBuilder) addSourceMac(f *config_parser.Function, macAddrs [][6]byte, outbound *routing.Outbound) (err error) {
	var addr16 [16]byte
	values := make([]netip.Prefix, 0, len(macAddrs))
	for _, mac := range macAddrs {
		copy(addr16[10:], mac[:])
		prefix := netip.PrefixFrom(netip.AddrFrom16(addr16), 128)
		values = append(values, prefix)
	}
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:            [16]byte{},
		Type:             uint8(consts.MatchType_Mac),
		Not:              f.Not,
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	b.rules = append(b.rules, set)
	return nil
}

func (b *RoutingMatcherBuilder) addIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:            [16]byte{},
		Type:             uint8(consts.MatchType_IpSet),
		Not:              f.Not,
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	b.rules = append(b.rules, set)
	return nil
}

func (b *RoutingMatcherBuilder) addPort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) (err error) {
	return outbound.ForEachLogicalOr(values, b.outboundToId, func(value [2]uint16, outboundId uint8) error {
		b.rules = append(b.rules, bpfMatchSet{
			Type: uint8(consts.MatchType_Port),
			Value: _bpfPortRange{
				PortStart: value[0],
				PortEnd:   value[1],
			}.Encode(),
			Not:              f.Not,
			Outbound:         outboundId,
			Mark:             outbound.Mark,
			Must:             outbound.Must,
			SkipWhileNoalive: outbound.SkipWhileNoalive,
		})
		return nil
	})
}

func (b *RoutingMatcherBuilder) addSourceIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:            [16]byte{},
		Type:             uint8(consts.MatchType_SourceIpSet),
		Not:              f.Not,
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	b.rules = append(b.rules, set)
	return nil
}

func (b *RoutingMatcherBuilder) addSourcePort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) (err error) {
	return outbound.ForEachLogicalOr(values, b.outboundToId, func(value [2]uint16, outboundId uint8) error {
		b.rules = append(b.rules, bpfMatchSet{
			Type: uint8(consts.MatchType_SourcePort),
			Value: _bpfPortRange{
				PortStart: value[0],
				PortEnd:   value[1],
			}.Encode(),
			Not:              f.Not,
			Outbound:         outboundId,
			Mark:             outbound.Mark,
			Must:             outbound.Must,
			SkipWhileNoalive: outbound.SkipWhileNoalive,
		})
		return nil
	})
}

func (b *RoutingMatcherBuilder) addL4Proto(f *config_parser.Function, values consts.L4ProtoType, outbound *routing.Outbound) (err error) {
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, bpfMatchSet{
		Value:            [16]byte{byte(values)},
		Type:             uint8(consts.MatchType_L4Proto),
		Not:              f.Not,
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	})
	return nil
}

func (b *RoutingMatcherBuilder) addIpVersion(f *config_parser.Function, values consts.IpVersionType, outbound *routing.Outbound) (err error) {
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, bpfMatchSet{
		Value:            [16]byte{byte(values)},
		Type:             uint8(consts.MatchType_IpVersion),
		Not:              f.Not,
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	})
	return nil
}

func (b *RoutingMatcherBuilder) addProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, outbound *routing.Outbound) (err error) {
	return outbound.ForEachLogicalOr(values, b.outboundToId, func(value [consts.TaskCommLen]byte, outboundId uint8) error {
		matchSet := bpfMatchSet{
			Type:             uint8(consts.MatchType_ProcessName),
			Not:              f.Not,
			Outbound:         outboundId,
			Mark:             outbound.Mark,
			Must:             outbound.Must,
			SkipWhileNoalive: outbound.SkipWhileNoalive,
		}
		copy(matchSet.Value[:], value[:])
		b.rules = append(b.rules, matchSet)
		return nil
	})
}

func (b *RoutingMatcherBuilder) addIfIndex(f *config_parser.Function, values []uint32, outbound *routing.Outbound) (err error) {
	return outbound.ForEachLogicalOr(values, b.outboundToId, func(value uint32, outboundId uint8) error {
		set := bpfMatchSet{
			Value:            [16]byte{},
			Type:             uint8(consts.MatchType_IfIndex),
			Not:              f.Not,
			Outbound:         outboundId,
			Mark:             outbound.Mark,
			Must:             outbound.Must,
			SkipWhileNoalive: outbound.SkipWhileNoalive,
		}
		binary.LittleEndian.PutUint32(set.Value[:], uint32(value))
		b.rules = append(b.rules, set)
		return nil
	})
}

func (b *RoutingMatcherBuilder) storeIfindex(index int, ifindex uint32) {
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()
	binary.LittleEndian.PutUint32(b.rules[index].Value[:], ifindex)
}

func (b *RoutingMatcherBuilder) addIfName(f *config_parser.Function, values []string, outbound *routing.Outbound) (err error) {
	return outbound.ForEachLogicalOr(values, b.outboundToId, func(value string, outboundId uint8) error {
		set := bpfMatchSet{
			Value:            [16]byte{},
			Type:             uint8(consts.MatchType_IfIndex),
			Not:              f.Not,
			Outbound:         outboundId,
			Mark:             outbound.Mark,
			Must:             outbound.Must,
			SkipWhileNoalive: outbound.SkipWhileNoalive,
		}
		index := len(b.rules)
		b.rules = append(b.rules, set)

		// Defer the ifmgr.Register call until BuildKernspace. Register may
		// fire its init callback synchronously and the callback writes to
		// bpf.RoutingMap, which is shared with the previously running plane
		// during a reload. Deferring keeps the validation phase side-effect
		// free; once BuildKernspace has uploaded the rule table, the init
		// callback patches the resolved ifindex into both the kernel rule and
		// the rule table shared with the userspace matcher.
		ifname := value
		b.kernspaceBuilders = append(b.kernspaceBuilders, func() error {
			updateIndex := func(ifindex uint32) error {
				binary.LittleEndian.PutUint32(set.Value[:], ifindex)
				if err := b.bpf.RoutingMap.Update(uint32(index), set, ebpf.UpdateAny); err != nil {
					return err
				}
				b.storeIfindex(index, ifindex)
				return nil
			}
			initlinkCallback := func(link netlink.Link) error {
				return updateIndex(uint32(link.Attrs().Index))
			}
			newlinkCallback := func(link netlink.Link) {
				log.Warnf("New link creation of '%v' is detected. Re-fetching ifindex for it.", link.Attrs().Name)
				if err := updateIndex(uint32(link.Attrs().Index)); err != nil {
					log.Errorf("Update failed: %v", err)
				}
			}
			dellinkCallback := func(link netlink.Link) {
				log.Warnf("Link deletion of '%v' is detected. Re-fetching ifindex once it is re-created.", link.Attrs().Name)
				if err := updateIndex(0); err != nil {
					log.Errorf("Update failed: %v", err)
				}
			}
			if err := b.ifmgr.RegisterSync(ifname, initlinkCallback, newlinkCallback, dellinkCallback); err != nil {
				return fmt.Errorf("register interface %q: %w", ifname, err)
			}
			return nil
		})
		return nil
	})
}

func (b *RoutingMatcherBuilder) addDscp(f *config_parser.Function, values []uint8, outbound *routing.Outbound) (err error) {
	return outbound.ForEachLogicalOr(values, b.outboundToId, func(value uint8, outboundId uint8) error {
		matchSet := bpfMatchSet{
			Type:             uint8(consts.MatchType_Dscp),
			Not:              f.Not,
			Outbound:         outboundId,
			Mark:             outbound.Mark,
			Must:             outbound.Must,
			SkipWhileNoalive: outbound.SkipWhileNoalive,
		}
		matchSet.Value[0] = value
		b.rules = append(b.rules, matchSet)
		return nil
	})
}

func (b *RoutingMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	fallback, err := config.ParseFunctionOrString(fallbackOutbound)
	if err != nil {
		return fmt.Errorf("invalid routing fallback: %w", err)
	}
	outbound, err := routing.ParseOutbound(fallback)
	if err != nil {
		return err
	}
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, bpfMatchSet{
		Type:             uint8(consts.MatchType_Fallback),
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	})
	return nil
}

func (b *RoutingMatcherBuilder) BuildKernspace() (err error) {
	// Slots active in the last committed build are replaced below. Only reset
	// the tail inherited from a larger previous rule set.
	if err = b.forEachStaleLpmSlot(func(i uint32) error {
		return b.bpf.LpmArrayMap.Update(i, b.bpf.UnusedLpmType, ebpf.UpdateAny)
	}); err != nil {
		return err
	}

	// Populate the active slots.
	for i, cidrs := range b.simulatedLpmTries {
		var keys []_bpfLpmKey
		var values []uint32
		for _, cidr := range cidrs {
			keys = append(keys, cidrToBpfLpmKey(cidr))
			values = append(values, 1)
		}
		m, err := b.bpf.newLpmMap(keys, values)
		if err != nil {
			return fmt.Errorf("newLpmMap: %w", err)
		}
		if err = b.bpf.LpmArrayMap.Update(uint32(i), m, ebpf.UpdateAny); err != nil {
			m.Close()
			return fmt.Errorf("Update: %w", err)
		}
		m.Close()
	}
	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != uint8(consts.MatchType_Fallback) {
		return fmt.Errorf("fallback rule MUST be the last")
	}
	routingsLen := uint32(len(b.rules))
	routingsKeys := common.ARangeU32(routingsLen)
	if _, err = b.bpf.RoutingMap.BatchUpdate(routingsKeys, b.rules, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("batch update routing map: %w", err)
	}
	log.Infof("Routing match set len: %v/%v", len(b.rules), consts.MaxMatchSetLen)

	// Run side-effects (e.g. interface watchers) once the routing table is
	// in place so that any callback writes patch the entries we just uploaded.
	for _, fn := range b.kernspaceBuilders {
		if err := fn(); err != nil {
			return fmt.Errorf("initialize interface routing: %w", err)
		}
	}
	b.kernspaceBuilders = nil
	b.bpf.activeLpmTrieCount = uint32(len(b.simulatedLpmTries))

	return nil
}

func (b *RoutingMatcherBuilder) forEachStaleLpmSlot(fn func(uint32) error) error {
	for i := uint32(len(b.simulatedLpmTries)); i < b.bpf.activeLpmTrieCount; i++ {
		if err := fn(i); err != nil {
			return fmt.Errorf("process stale LPM slot at index %d: %w", i, err)
		}
	}
	return nil
}

func (b *RoutingMatcherBuilder) BuildUserspace() (matcher *RoutingMatcher, err error) {
	// Build domainMatcher
	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	// Build Ip matcher.
	var lpmMatcher []*trie.Trie
	for _, prefixes := range b.simulatedLpmTries {
		t, err := trie.NewTrieFromPrefixes(prefixes)
		if err != nil {
			return nil, err
		}
		lpmMatcher = append(lpmMatcher, t)
	}
	if err = domainMatcher.Build(); err != nil {
		return nil, err
	}

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != uint8(consts.MatchType_Fallback) {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}

	return &RoutingMatcher{
		lpmMatcher:    lpmMatcher,
		domainMatcher: domainMatcher,
		matches:       b.rules,
		rulesMu:       &b.rulesMu,
	}, nil
}
