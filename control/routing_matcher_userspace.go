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
	destinations  []destinationPredicate
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
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	return m.matchRange(0, len(m.matches), routingInput{
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

type routingInput struct {
	sourceAddr, destAddr, mac []byte
	sourcePort, destPort      uint16
	ipVersion                 consts.IpVersionType
	l4proto                   consts.L4ProtoType
	domain                    string
	processName               [16]uint8
	ifindex                   uint32
	tos                       uint8
	trustedDomainBitmap       [][]uint32
}

// Caller holds rulesMu. Absolute indices keep all predicates on the same
// domain bitmap and dynamic client/interface tables.
func (m *RoutingMatcher) matchRange(start, end int, p routingInput) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	if len(p.sourceAddr) != net.IPv6len || len(p.destAddr) != net.IPv6len || len(p.mac) != net.IPv6len {
		return 0, 0, false, fmt.Errorf("bad address length")
	}

	bin128s := make([]string, consts.MatchType_Mac+1)
	bin128s[consts.MatchType_IpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(p.destAddr)), 128))
	bin128s[consts.MatchType_SourceIpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(p.sourceAddr)), 128))
	bin128s[consts.MatchType_Mac] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(p.mac)), 128))

	var domainMatchBitmap []uint32
	var domainBumpBitmap []uint32
	simulateKernel := len(p.trustedDomainBitmap) > 1
	if simulateKernel {
		domainBumpBitmap = p.trustedDomainBitmap[1]
	}
	if len(p.trustedDomainBitmap) > 0 && p.trustedDomainBitmap[0] != nil {
		domainMatchBitmap = p.trustedDomainBitmap[0]
	} else if p.domain != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(p.domain)
	}

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
			lpmIndex := uint32(binary.LittleEndian.Uint16(match.Value[:]))
			m := m.lpmMatcher[lpmIndex]
			if m.HasPrefix(bin128s[match.Type]) {
				goodSubrule = true
			}
		case consts.MatchType_DomainSet:
			if len(domainMatchBitmap) > i/32 && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			} else if len(domainBumpBitmap) > i/32 && (domainBumpBitmap[i/32]>>(i%32))&1 > 0 {
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
			return 0, 0, false, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		outbound := consts.OutboundIndex(match.Outbound)
		if outbound != consts.OutboundLogicalOr {
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

		if outbound&consts.OutboundLogicalMask !=
			consts.OutboundLogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				if match.CaptureFlags != 0 {
					needControlPlaneRouting = false
					continue
				}
				if outbound == consts.OutboundControlPlaneRouting && !simulateKernel {
					needControlPlaneRouting = false
					continue
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
					return consts.OutboundControlPlaneRouting, 0, must, nil
				}
				if outbound == consts.OutboundMustRules {
					must = true
					continue
				}
				if must {
					match.Must = true
				}
				return outbound, match.Mark, match.Must, nil
			}
			badRule = false
			needControlPlaneRouting = false
		}
	}
	return 0, 0, false, fmt.Errorf("no match set hit")
}
