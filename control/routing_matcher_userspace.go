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
// the kernel's uncertain domain matches while skipping Surge's injected
// capture rule, so the original routing decision can be reconstructed.
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
	if len(sourceAddr) != net.IPv6len || len(destAddr) != net.IPv6len || len(mac) != net.IPv6len {
		return 0, 0, false, fmt.Errorf("bad address length")
	}

	bin128s := make([]string, consts.MatchType_Mac+1)
	bin128s[consts.MatchType_IpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(destAddr)), 128))
	bin128s[consts.MatchType_SourceIpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(sourceAddr)), 128))
	bin128s[consts.MatchType_Mac] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(mac)), 128))

	var domainMatchBitmap []uint32
	var domainBumpBitmap []uint32
	simulateKernel := len(trustedDomainBitmap) > 1
	if simulateKernel {
		domainBumpBitmap = trustedDomainBitmap[1]
	}
	if len(trustedDomainBitmap) > 0 && trustedDomainBitmap[0] != nil {
		domainMatchBitmap = trustedDomainBitmap[0]
	} else if domain != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(domain)
	}
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	captureIndex := -1
	ipCaptureIndex := -1
	if simulateKernel {
		captureIndex = m.captureRuleIndex(consts.MatchType_DomainSet)
		ipCaptureIndex = m.captureRuleIndex(consts.MatchType_IpSet)
	}

	goodSubrule := false
	uncertainSubrule := false
	needControlPlaneRouting := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch consts.MatchType(match.Type) {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			lpmIndex := uint32(binary.LittleEndian.Uint16(match.Value[:]))
			m := m.lpmMatcher[lpmIndex]
			if m != nil && m.HasPrefix(bin128s[match.Type]) {
				goodSubrule = true
			}
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			} else if domainBumpBitmap != nil && (domainBumpBitmap[i/32]>>(i%32))&1 > 0 {
				uncertainSubrule = true
			}
		case consts.MatchType_Port:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if destPort >= portStart &&
				destPort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_SourcePort:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if sourcePort >= portStart &&
				sourcePort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_IpVersion:
			// LittleEndian
			if ipVersion&consts.IpVersionType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_L4Proto:
			// LittleEndian
			if l4proto&consts.L4ProtoType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_ProcessName:
			if processName[0] != 0 && match.Value == processName {
				goodSubrule = true
			}
		case consts.MatchType_IfIndex:
			if ifindex != 0 && ifindex == binary.LittleEndian.Uint32(match.Value[:]) {
				goodSubrule = true
			}
		case consts.MatchType_Dscp:
			if tos == match.Value[0] {
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
				if outbound == consts.OutboundControlPlaneRouting && (!simulateKernel || i == captureIndex || i == ipCaptureIndex) {
					needControlPlaneRouting = false
					continue
				}
				if match.SkipWhileNoalive &&
					outbound >= consts.OutboundUserDefinedMin &&
					outbound < consts.OutboundMustRules &&
					m.outboundUsable != nil &&
					!m.outboundUsable(uint8(outbound), l4proto, ipVersion) {
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

// Locate the two capture shapes: TCP + domain for HTTP processing, and
// TCP/UDP + destination IP for address rewriting. API rules may precede them.
// The caller holds rulesMu because interface matching can update match values.
func (m *RoutingMatcher) captureRuleIndex(kind consts.MatchType) int {
	proto := consts.L4ProtoType_TCP
	if kind == consts.MatchType_IpSet {
		proto |= consts.L4ProtoType_UDP
	}
	for i := 1; i < len(m.matches); i++ {
		protocol, target := m.matches[i-1], m.matches[i]
		if i > 1 && m.matches[i-2].Outbound&uint8(consts.OutboundLogicalMask) == uint8(consts.OutboundLogicalMask) {
			continue
		}
		if protocol.Type == uint8(consts.MatchType_L4Proto) && protocol.Value[0] == uint8(proto) && !protocol.Not &&
			protocol.Outbound == uint8(consts.OutboundLogicalAnd) && target.Type == uint8(kind) && !target.Not &&
			target.Outbound == uint8(consts.OutboundControlPlaneRouting) {
			return i
		}
	}
	return -1
}
