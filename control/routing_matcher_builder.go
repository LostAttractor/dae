/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync"

	"github.com/daeuniverse/dae/component/network"
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
	ifmgr              *network.InterfaceManager
	bpf                *BPFState
	rules              []bpfMatchSet
	rulesMu            sync.RWMutex
	simulatedLpmTries  [][]netip.Prefix
	clientSetSlots     map[string]int
	destination        DestinationProgram
	flow               FlowProgram
	routing            RoutingProgram
	kernelLpmLen       int
	domainSetIDs       map[string]uint32
	staticLpmIDs       map[string]int
	simulatedDomainSet []routing.DomainSet

	// kernspaceBuilders collect side effects that must run against the
	// shared eBPF state (e.g. registering interface watchers that update
	// RoutingMap on link events). They are deferred until BuildKernspace so
	// that NewRoutingMatcherBuilder stays free of BPF map writes and can
	// run during the validation phase of a reload.
	kernspaceBuilders []func() error
}

func NewRoutingMatcherBuilder(rules []*config_parser.RoutingRule, outboundName2Id map[string]uint8, bpf *BPFState, fallback config.FunctionOrString, ifmgr *network.InterfaceManager, capture *routingCapture, destinations routing.DestinationRewrites) (b *RoutingMatcherBuilder, err error) {
	b = &RoutingMatcherBuilder{outboundName2Id: outboundName2Id, ifmgr: ifmgr, bpf: bpf, clientSetSlots: make(map[string]int), domainSetIDs: make(map[string]uint32), staticLpmIDs: make(map[string]int)}
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
	if capture != nil {
		if capture.before < 0 || capture.before > len(rules) {
			return nil, fmt.Errorf("invalid API bypass range")
		}
		if err = rulesBuilder.Apply(rules[:capture.before]); err != nil {
			return nil, err
		}
		rules = rules[capture.before:]
	}
	applyEffect := func(filter []*config_parser.Function, action consts.MatchAction, flags uint8) error {
		if err := rulesBuilder.ApplyPredicate(filter, &routing.Outbound{Name: "direct"}); err != nil {
			return err
		}
		tail := &b.rules[len(b.rules)-1]
		tail.Action, tail.CaptureFlags = uint8(action), flags
		return nil
	}
	b.destination.start = len(b.rules)
	for _, rule := range destinations {
		// Capture retains the complete predicate, including DNS-backed domains.
		if err = applyEffect(rule.Filter, consts.MatchActionCapture, captureDestination); err != nil {
			return nil, fmt.Errorf("destination capture: %w", err)
		}
	}
	if capture != nil {
		for _, predicate := range mitmCapturePredicates(capture.requestRouting) {
			if err = applyEffect(predicate, consts.MatchActionCapture, captureHTTP|captureHTTPRequest); err != nil {
				return nil, fmt.Errorf("HTTP request capture: %w", err)
			}
		}
	}
	b.destination.end = len(b.rules)
	b.flow.start = b.destination.end
	if capture != nil {
		for _, rule := range capture.controls {
			if rule.Action != consts.MatchActionMust && rule.Action != consts.MatchActionBump {
				return nil, fmt.Errorf("invalid flow action %d", rule.Action)
			}
			if err = applyEffect(rule.Filter, rule.Action, 0); err != nil {
				return nil, fmt.Errorf("flow control: %w", err)
			}
		}
		for _, predicate := range mitmCapturePredicates(capture.http) {
			if err = applyEffect(predicate, consts.MatchActionCapture, captureHTTP); err != nil {
				return nil, fmt.Errorf("HTTP capture: %w", err)
			}
		}
	}
	if len(b.rules) != b.flow.start {
		b.rules = append(b.rules, bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)})
	}
	b.flow.end = len(b.rules)
	b.routing.start = b.flow.end

	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}

	if err = b.addFallback(fallback); err != nil {
		return nil, err
	}
	b.routing.end = len(b.rules)
	b.kernelLpmLen = len(b.simulatedLpmTries)
	for _, rule := range destinations {
		entry := destinationPredicate{start: len(b.rules), targets: rule.To}
		for _, f := range rule.Filter {
			entry.domain = entry.domain || f.Name == "domain"
		}
		if err = rulesBuilder.ApplyPredicate(rule.Filter, &routing.Outbound{Name: "direct"}); err != nil {
			return nil, fmt.Errorf("destination predicate: %w", err)
		}
		b.rules[len(b.rules)-1].Action = uint8(consts.MatchActionMatch)
		b.rules = append(b.rules, bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMiss)})
		entry.end = len(b.rules)
		b.destination.predicates = append(b.destination.predicates, entry)
	}

	// Only the kernel program consumes routing-map capacity. Destination
	// predicates share domain/LPM IDs but do not occupy kernel instruction slots.
	if b.routing.end > consts.MaxMatchSetLen {
		return nil, fmt.Errorf("too many kernel routing match sets: %d > %d (MaxMatchSetLen)", b.routing.end, consts.MaxMatchSetLen)
	}
	if len(b.rules)-b.routing.end > consts.MaxMatchSetLen*2 {
		return nil, fmt.Errorf("too many destination match sets: %d > %d", len(b.rules)-b.routing.end, consts.MaxMatchSetLen*2)
	}
	// The shared predicate compiler also serves DNS. Translate its logical
	// edges once into instruction actions; the eBPF ABI never overloads an
	// outbound ID with a control or logical action.
	for i := range b.rules {
		switch consts.OutboundIndex(b.rules[i].Outbound) {
		case consts.OutboundLogicalOr:
			b.rules[i].Action, b.rules[i].Outbound = uint8(consts.MatchActionOr), 0
		case consts.OutboundLogicalAnd:
			b.rules[i].Action, b.rules[i].Outbound = uint8(consts.MatchActionAnd), 0
		}
	}

	// Validate skip_while_noalive usage. The flag is carried by every match
	// set of a rule but only takes effect on the rule tail.
	for i := range b.rules {
		r := &b.rules[i]
		if !r.SkipWhileNoalive {
			continue
		}
		outbound := consts.OutboundIndex(r.Outbound)
		if r.Action != uint8(consts.MatchActionRoute) {
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
	for _, rule := range b.rules[b.routing.start:b.routing.end] {
		if rule.Action != uint8(consts.MatchActionRoute) {
			continue
		}
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
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, bpfMatchSet{
		Type:             uint8(consts.MatchType_DomainSet),
		Value:            value,
		Not:              f.Not,
		Outbound:         outboundId,
		Mark:             outbound.Mark,
		Must:             outbound.Must,
		SkipWhileNoalive: outbound.SkipWhileNoalive,
	})
	return nil
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

// ClientSets lists the named client sets referenced by routing rules.
func (b *RoutingMatcherBuilder) ClientSets() []string {
	return slices.Sorted(maps.Keys(b.clientSetSlots))
}

// SetClientMembers updates both matchers for a routing-referenced set; other
// sets need no routing update. During preparation, active must be false and
// BuildKernspace publishes the prepared members on activation. Active updates
// replace the kernel map before publishing the userspace trie.
func (b *RoutingMatcherBuilder) SetClientMembers(matcher *RoutingMatcher, name string, members [][6]byte, active bool) error {
	slot, exists := b.clientSetSlots[name]
	if !exists {
		return nil
	}
	prefixes := sourceMacPrefixes(members)
	next, err := trie.NewTrieFromPrefixes(prefixes)
	if err != nil {
		return fmt.Errorf("build client set %q: %w", name, err)
	}
	var kernelMap *ebpf.Map
	if active && slot < b.kernelLpmLen {
		kernelMap, err = b.bpf.newLpmMap(prefixes)
		if err != nil {
			return fmt.Errorf("build kernel client set %q: %w", name, err)
		}
		defer kernelMap.Close()
	}
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()
	if active && slot < b.kernelLpmLen {
		if err := b.bpf.LpmArrayMap.Update(uint32(slot), kernelMap, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update kernel client set %q: %w", name, err)
		}
	}
	b.simulatedLpmTries[slot] = prefixes
	matcher.lpmMatcher[slot] = next
	return nil
}

func (b *RoutingMatcherBuilder) addIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	lpmTrieIndex := b.internLPM(values)
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
	lpmTrieIndex := b.internLPM(values)
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

func (b *RoutingMatcherBuilder) updateIfindex(index int, ifindex uint32, active bool) error {
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()
	current := b.rules[index]
	binary.LittleEndian.PutUint32(current.Value[:], ifindex)
	if active && index < b.routing.end {
		if err := b.bpf.RoutingMap.Update(uint32(index), current, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	b.rules[index] = current
	return nil
}

func (b *RoutingMatcherBuilder) addInterface(f *config_parser.Function, values []string, outbound *routing.Outbound) (err error) {
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
		interfaceName := value
		b.kernspaceBuilders = append(b.kernspaceBuilders, func() error {
			updateIndex := func(ifindex uint32) error {
				return b.updateIfindex(index, ifindex, true)
			}
			initlinkCallback := func(link netlink.Link) error {
				return updateIndex(uint32(link.Attrs().Index))
			}
			newlinkCallback := func(link netlink.Link) {
				log.WithField("interface", link.Attrs().Name).Debug("Updating routing rule for new interface")
				if err := updateIndex(uint32(link.Attrs().Index)); err != nil {
					log.WithError(err).WithField("interface", link.Attrs().Name).Error("Could not update interface routing rule")
				}
			}
			dellinkCallback := func(link netlink.Link) {
				log.WithField("interface", link.Attrs().Name).Debug("Clearing routing rule for removed interface")
				if err := updateIndex(0); err != nil {
					log.WithError(err).WithField("interface", link.Attrs().Name).Error("Could not update interface routing rule")
				}
			}
			if err := b.ifmgr.RegisterSync(interfaceName, initlinkCallback, newlinkCallback, dellinkCallback); err != nil {
				return fmt.Errorf("register interface %q: %w", interfaceName, err)
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
	for i, cidrs := range b.simulatedLpmTries[:b.kernelLpmLen] {
		m, err := b.bpf.newLpmMap(cidrs)
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
	if b.routing.end == 0 || b.rules[b.routing.end-1].Type != uint8(consts.MatchType_Fallback) {
		return fmt.Errorf("fallback rule MUST be the last")
	}
	routingsLen := uint32(b.routing.end)
	routingsKeys := common.ARangeU32(routingsLen)
	if _, err = b.bpf.RoutingMap.BatchUpdate(routingsKeys, b.rules[:b.routing.end], &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("batch update routing map: %w", err)
	}
	log.Debugf("Kernel match sets: %d/%d (bypass=%d, destination=%d, flow=%d, routing=%d); userspace destination match sets: %d", b.routing.end, consts.MaxMatchSetLen, b.destination.start, b.destination.end-b.destination.start, b.flow.end-b.flow.start, b.routing.end-b.routing.start, len(b.rules)-b.routing.end)

	// Run side-effects (e.g. interface watchers) once the routing table is
	// in place so that any callback writes patch the entries we just uploaded.
	for _, fn := range b.kernspaceBuilders {
		if err := fn(); err != nil {
			return fmt.Errorf("initialize interface routing: %w", err)
		}
	}
	b.kernspaceBuilders = nil
	b.bpf.activeLpmTrieCount = uint32(b.kernelLpmLen)

	return nil
}

func (b *RoutingMatcherBuilder) forEachStaleLpmSlot(fn func(uint32) error) error {
	for i := uint32(b.kernelLpmLen); i < b.bpf.activeLpmTrieCount; i++ {
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
	if b.routing.end == 0 || b.rules[b.routing.end-1].Type != uint8(consts.MatchType_Fallback) {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}

	return &RoutingMatcher{
		destination:   b.destination,
		flow:          b.flow,
		routing:       b.routing,
		lpmMatcher:    lpmMatcher,
		domainMatcher: domainMatcher,
		matches:       b.rules,
		rulesMu:       &b.rulesMu,
	}, nil
}
