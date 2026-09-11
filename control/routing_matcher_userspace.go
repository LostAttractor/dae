/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/pkg/trie"
)

type RoutingMatcher struct {
	defaultProfileID uint32
	profiles         map[uint32][]routingSpan
	destination      DestinationProgram
	flow             FlowProgram
	routing          RoutingProgram
	lpmMatcher       []*trie.Trie
	domainMatcher    routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	matches []bpfMatchSet
	rulesMu *sync.RWMutex

	// outboundUsable reports whether an outbound group can serve the given
	// network type; it backs skip_while_noalive rule evaluation. It may be
	// nil (e.g. in tests), in which case every group is considered usable.
	outboundUsable func(outbound uint8, l4proto consts.L4ProtoType, ipVersion consts.IpVersionType) bool
}

// match executes the same bytecode as kern/routing.h. Captures preserve userspace routing decisions.
func (m *RoutingMatcher) match(p routingInput) (consts.OutboundIndex, uint32, bool, error) {
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	if p.profileID == 0 {
		p.profileID = m.defaultProfileID
	}
	spans, ok := m.profiles[p.profileID]
	if !ok {
		return 0, 0, false, fmt.Errorf("unknown routing profile %d", p.profileID)
	}
	result, err := m.evaluateSpans(spans, p)
	return result.outbound, result.mark, result.must, err
}

type routingEvaluation struct {
	outbound     consts.OutboundIndex
	mark         uint32
	must         bool
	captureFlags uint8
	matched      bool // DestinationProgram predicate result.
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

	profiles := make(map[uint32][]routingSpan, len(b.profiles))
	for _, profile := range b.profiles {
		profiles[profile.ID] = append([]routingSpan(nil), profile.Spans...)
	}

	return &RoutingMatcher{
		defaultProfileID: b.defaultProfileID,
		destination:      b.destination,
		flow:             b.flow,
		routing:          b.routing,
		profiles:         profiles,
		lpmMatcher:       lpmMatcher,
		domainMatcher:    domainMatcher,
		matches:          b.rules,
		rulesMu:          &b.rulesMu,
	}, nil
}

// Caller holds rulesMu. Complete rules never cross a physical span boundary,
// so the same relative jumps work for profiles and destination predicates.
func (m *RoutingMatcher) evaluateSpans(spans []routingSpan, p routingInput) (routingEvaluation, error) {
	if !p.src.IsValid() || !p.dst.IsValid() {
		return routingEvaluation{}, fmt.Errorf("invalid routing address")
	}
	predicates := routingPredicates{input: p, ipVersion: consts.IpVersionFromAddr(p.dst.Addr())}
	simulateKernel := (p.kernel || p.domainBumpBitmap != nil) && p.stage != routeAfterTarget
	var subrule, must predicateResult
	var ruleUnknown, flowBump bool
	var captureFlags uint8
	for _, span := range spans {
		start := span.Start
		if p.stage == routeAfterTarget {
			start = max(start, uint32(m.flow.start))
		}
		for i := start; i < span.End; {
			match := &m.matches[i]
			action := consts.MatchAction(match.Action)
			distance := uint32(1)
			var clause predicateResult
			if subrule != predicateMatch {
				result, err := predicates.match(m, match)
				if err != nil {
					return routingEvaluation{}, err
				}
				subrule = max(subrule, result)
			}
			if action == consts.MatchActionOr {
				if subrule == predicateMatch {
					distance = match.Mark
				}
				goto advance
			}
			clause, subrule = subrule, predicateMiss
			if match.Flags&matchFlagNot != 0 {
				clause = predicateMatch - clause
			}
			if clause == predicateMiss {
				if action == consts.MatchActionAnd {
					distance = match.Mark
				}
				goto nextRule
			}
			ruleUnknown = ruleUnknown || clause == predicateUnknown
			if action == consts.MatchActionAnd {
				goto advance
			}
			switch action {
			case consts.MatchActionMust:
				if !ruleUnknown {
					must = predicateMatch
				} else {
					must = max(must, predicateUnknown)
				}
			case consts.MatchActionBump:
				flowBump = true
			case consts.MatchActionCapture:
				captureFlags |= (match.Flags >> matchCaptureShift) & 7
				if simulateKernel && captureFlags&(captureDestination|captureHTTPRequest) != 0 {
					return routingEvaluation{outbound: consts.OutboundControlPlaneRouting, captureFlags: captureFlags}, nil
				}
			case consts.MatchActionFlowEnd:
				if (simulateKernel && flowBump) || must == predicateUnknown {
					return routingEvaluation{outbound: consts.OutboundControlPlaneRouting, must: must == predicateMatch, captureFlags: captureFlags}, nil
				}
			case consts.MatchActionMatch:
				return routingEvaluation{matched: true}, nil
			case consts.MatchActionMiss:
				return routingEvaluation{}, nil
			case consts.MatchActionRoute:
				if match.Flags&matchFlagSkipNoalive != 0 && m.outboundUsable != nil && !m.outboundUsable(match.Outbound, p.l4proto, predicates.ipVersion) {
					goto nextRule
				}
				if ruleUnknown {
					return routingEvaluation{outbound: consts.OutboundControlPlaneRouting, must: must == predicateMatch, captureFlags: captureFlags}, nil
				}
				forced := must == predicateMatch || match.Flags&matchFlagMust != 0
				if simulateKernel && !forced && p.dst.Port() == 53 && match.Flags&matchFlagBypass == 0 {
					captureFlags |= 8
				}
				return routingEvaluation{outbound: consts.OutboundIndex(match.Outbound), mark: match.Mark, must: forced, captureFlags: captureFlags}, nil
			default:
				return routingEvaluation{}, fmt.Errorf("unknown match action: %d", action)
			}
		nextRule:
			ruleUnknown = false
		advance:
			if distance == 0 || distance > span.End-i {
				return routingEvaluation{}, fmt.Errorf("invalid routing jump at %d: %d", i, distance)
			}
			i += distance
		}
	}
	return routingEvaluation{}, fmt.Errorf("no match set hit")
}

// Match evaluates the default policy for a byte-oriented packet description.
// Control-plane routing uses routingInput to retain the kernel-selected profile.
func (m *RoutingMatcher) Match(source, dest []byte, sport, dport uint16, _ consts.IpVersionType, proto consts.L4ProtoType, domain string, pname [16]byte, ifindex uint32, dscp uint8, mac []byte, bitmaps ...[]uint32) (consts.OutboundIndex, uint32, bool, error) {
	if len(source) != 16 || len(dest) != 16 || len(mac) != 16 {
		return 0, 0, false, fmt.Errorf("routing addresses must have 16 bytes")
	}
	p := routingInput{
		src:     netip.AddrPortFrom(netip.AddrFrom16([16]byte(source)).Unmap(), sport),
		dst:     netip.AddrPortFrom(netip.AddrFrom16([16]byte(dest)).Unmap(), dport),
		l4proto: proto, domain: domain, processName: pname, ifindex: ifindex, dscp: dscp, mac: [6]byte(mac[10:]),
	}
	if len(bitmaps) > 0 {
		p.domainBitmap = bitmaps[0]
	}
	if len(bitmaps) > 1 {
		p.domainBumpBitmap = bitmaps[1]
		p.kernel = true
	}
	return m.match(p)
}
