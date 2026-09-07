/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
)

type RoutingMatcher struct {
	destination   DestinationProgram
	flow          FlowProgram
	routing       RoutingProgram
	lpmMatcher    []*trie.Trie
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	matches []bpfMatchSet
	rulesMu *sync.RWMutex

	// outboundUsable reports whether an outbound group can serve the given
	// network type; it backs skip_while_noalive rule evaluation. It may be
	// nil (e.g. in tests), in which case every group is considered usable.
	outboundUsable func(outbound uint8, l4proto consts.L4ProtoType, ipVersion consts.IpVersionType) bool
}

// Match is modified from kern/tproxy.c; please keep sync. An optional routing
// bitmap replaces hostname matching. Supplying a second (bump) bitmap models
// the kernel's uncertain domain matches. Capture actions do not change
// userspace routing decisions.
func (m *RoutingMatcher) Match(
	sourceAddr []byte,
	destAddr []byte,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	ifindex uint32,
	tos uint8,
	mac []byte,
	trustedDomainBitmap ...[]uint32,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	return m.match(routingInput{
		sourceAddr:          sourceAddr,
		destAddr:            destAddr,
		sourcePort:          sourcePort,
		destPort:            destPort,
		ipVersion:           ipVersion,
		l4proto:             l4proto,
		domain:              domain,
		processName:         processName,
		ifindex:             ifindex,
		tos:                 tos,
		mac:                 mac,
		trustedDomainBitmap: trustedDomainBitmap,
	})
}

// Match the selected stage using the shared flow input.
func (m *RoutingMatcher) match(p routingInput) (consts.OutboundIndex, uint32, bool, error) {
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	end := m.routing.end
	if end == 0 {
		end = len(m.matches)
	}
	start := 0
	if p.afterTarget {
		start = m.flow.start
	}
	result, err := m.evaluateRange(start, end, p)
	return result.outbound, result.mark, result.must, err
}

type routingEvaluation struct {
	outbound     consts.OutboundIndex
	mark         uint32
	must         bool
	captureFlags uint8
	matched      bool // DestinationProgram predicate result.
}

// Caller holds rulesMu. Domain and LPM IDs are independent of instruction
// ranges, so kernel and userspace-only routing predicates share their resources.
func (m *RoutingMatcher) evaluateRange(start, end int, p routingInput) (routingEvaluation, error) {
	if len(p.sourceAddr) != net.IPv6len || len(p.destAddr) != net.IPv6len || len(p.mac) != net.IPv6len {
		return routingEvaluation{}, fmt.Errorf("bad address length")
	}

	bin128s := make([]string, consts.MatchType_Mac+1)
	bin128s[consts.MatchType_IpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(p.destAddr)), 128))
	bin128s[consts.MatchType_SourceIpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(p.sourceAddr)), 128))
	bin128s[consts.MatchType_Mac] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(p.mac)), 128))

	var domainMatchBitmap []uint32
	var domainBumpBitmap []uint32
	hasBump := len(p.trustedDomainBitmap) > 1
	simulateKernel := hasBump && !p.afterTarget
	if hasBump {
		domainBumpBitmap = p.trustedDomainBitmap[1]
	}
	if len(p.trustedDomainBitmap) > 0 && p.trustedDomainBitmap[0] != nil {
		domainMatchBitmap = p.trustedDomainBitmap[0]
	} else if p.domain != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(p.domain)
	}

	var must, pendingMust, flowBump bool
	var captureFlags uint8
	goodSubrule := false
	uncertainSubrule := false
	needControlPlaneRouting := false
	badRule := false
	for i := start; i < end; i++ {
		match := m.matches[i]
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch consts.MatchType(match.Type) {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			lpmIndex := binary.LittleEndian.Uint32(match.Value[:])
			m := m.lpmMatcher[lpmIndex]
			if m.HasPrefix(bin128s[match.Type]) {
				goodSubrule = true
			}
		case consts.MatchType_DomainSet:
			id := binary.LittleEndian.Uint32(match.Value[:])
			if int(id/32) < len(domainMatchBitmap) && (domainMatchBitmap[id/32]>>(id%32))&1 > 0 {
				goodSubrule = true
			} else if int(id/32) < len(domainBumpBitmap) && (domainBumpBitmap[id/32]>>(id%32))&1 > 0 {
				uncertainSubrule = true
			}
		case consts.MatchType_Port:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if p.destPort >= portStart &&
				p.destPort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_SourcePort:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if p.sourcePort >= portStart &&
				p.sourcePort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_IpVersion:
			// LittleEndian
			if p.ipVersion&consts.IpVersionType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_L4Proto:
			// LittleEndian
			if p.l4proto&consts.L4ProtoType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_ProcessName:
			if p.processName[0] != 0 && match.Value == p.processName {
				goodSubrule = true
			}
		case consts.MatchType_IfIndex:
			if p.ifindex != 0 && p.ifindex == binary.LittleEndian.Uint32(match.Value[:]) {
				goodSubrule = true
			}
		case consts.MatchType_Dscp:
			if p.tos == match.Value[0] {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return routingEvaluation{}, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		outbound := consts.OutboundIndex(match.Outbound)
		action := consts.MatchAction(match.Action)
		if action != consts.MatchActionOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if !goodSubrule && uncertainSubrule {
				needControlPlaneRouting = true
			} else if goodSubrule == match.Not {
				// This subrule does not hit.
				badRule = true
			}

			// Reset goodSubrule.
			goodSubrule = false
			uncertainSubrule = false
		}

		if action != consts.MatchActionOr && action != consts.MatchActionAnd {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				switch action {
				case consts.MatchActionMust:
					if needControlPlaneRouting {
						pendingMust = true
					} else {
						must = true
					}
					goto nextRule
				case consts.MatchActionBump:
					flowBump = true
					goto nextRule
				case consts.MatchActionCapture:
					captureFlags |= match.CaptureFlags
					if simulateKernel && captureFlags&(captureDestination|captureHTTPRequest) != 0 {
						return routingEvaluation{outbound: consts.OutboundControlPlaneRouting, captureFlags: captureFlags}, nil
					}
					goto nextRule
				case consts.MatchActionFlowEnd:
					if (simulateKernel && flowBump) || pendingMust && !must {
						return routingEvaluation{outbound: consts.OutboundControlPlaneRouting, must: must, captureFlags: captureFlags}, nil
					}
					goto nextRule
				case consts.MatchActionMatch:
					return routingEvaluation{matched: true}, nil
				case consts.MatchActionMiss:
					return routingEvaluation{}, nil
				case consts.MatchActionRoute:
				default:
					return routingEvaluation{}, fmt.Errorf("unknown match action: %d", action)
				}
				if match.SkipWhileNoalive &&
					outbound >= consts.OutboundUserDefinedMin &&
					outbound < consts.OutboundMustRules &&
					m.outboundUsable != nil &&
					!m.outboundUsable(uint8(outbound), p.l4proto, p.ipVersion) {
					// The rule is conditional on the connectivity of the
					// target outbound group. Treat an unavailable group as
					// not hit and continue with the next rule.
					needControlPlaneRouting = false
					continue
				}
				if needControlPlaneRouting {
					return routingEvaluation{outbound: consts.OutboundControlPlaneRouting, must: must, captureFlags: captureFlags}, nil
				}
				return routingEvaluation{outbound: outbound, mark: match.Mark, must: must || match.Must, captureFlags: captureFlags}, nil
			}
		nextRule:
			badRule = false
			needControlPlaneRouting = false
		}
	}
	return routingEvaluation{}, fmt.Errorf("no match set hit")
}
