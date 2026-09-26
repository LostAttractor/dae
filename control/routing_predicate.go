// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/trie"
)

// Same truth ordering as match_result in kern/routing.h. OR takes max;
// negation is predicateMatch-result, leaving an ambiguous domain unchanged.
type predicateResult uint8

const (
	predicateMiss predicateResult = iota
	predicateUnknown
	predicateMatch
)

// Per-evaluation input caches: a skipped predicate prepares nothing.
type routingPredicates struct {
	input        routingInput
	ipVersion    consts.IpVersionType
	lpmKeys      [consts.MatchType_Mac + 1]string
	domainLoaded bool
}

func (p *routingPredicates) lpmKey(kind consts.MatchType) string {
	if key := p.lpmKeys[kind]; key != "" {
		return key
	}
	var address netip.Addr
	switch kind {
	case consts.MatchType_IpSet:
		address = p.input.dst.Addr()
	case consts.MatchType_SourceIpSet:
		address = p.input.src.Addr()
	case consts.MatchType_Mac:
		var mac [16]byte
		copy(mac[10:], p.input.mac[:])
		address = netip.AddrFrom16(mac)
	}
	key := trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(address.As16()), 128))
	p.lpmKeys[kind] = key
	return key
}

func (p *routingPredicates) match(m *RoutingMatcher, match *bpfMatchSet) (predicateResult, error) {
	var hit bool
	switch consts.MatchType(match.Type) {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
		index := binary.LittleEndian.Uint32(match.Value[:])
		hit = m.lpmMatcher[index].HasPrefix(p.lpmKey(consts.MatchType(match.Type)))
	case consts.MatchType_DomainSet:
		if !p.domainLoaded {
			if p.input.domainBitmap == nil && p.input.domain != "" {
				p.input.domainBitmap = m.domainMatcher.MatchDomainBitmap(p.input.domain)
			}
			p.domainLoaded = true
		}
		id := binary.LittleEndian.Uint32(match.Value[:])
		if int(id/32) < len(p.input.domainBitmap) && (p.input.domainBitmap[id/32]>>(id%32))&1 != 0 {
			return predicateMatch, nil
		}
		if int(id/32) < len(p.input.domainBumpBitmap) && (p.input.domainBumpBitmap[id/32]>>(id%32))&1 != 0 {
			return predicateUnknown, nil
		}
		return predicateMiss, nil
	case consts.MatchType_Port:
		start, end := ParsePortRange(match.Value[:])
		hit = start <= p.input.dst.Port() && p.input.dst.Port() <= end
	case consts.MatchType_SourcePort:
		start, end := ParsePortRange(match.Value[:])
		hit = start <= p.input.src.Port() && p.input.src.Port() <= end
	case consts.MatchType_IpVersion:
		hit = p.ipVersion&consts.IpVersionType(match.Value[0]) != 0
	case consts.MatchType_L4Proto:
		hit = p.input.l4proto&consts.L4ProtoType(match.Value[0]) != 0
	case consts.MatchType_ProcessName:
		hit = p.input.processName[0] != 0 && match.Value == p.input.processName
	case consts.MatchType_IfIndex:
		index := binary.LittleEndian.Uint32(match.Value[:])
		hit = index != 0 && (p.input.ifindex == index || p.input.physinif == index)
	case consts.MatchType_Dscp:
		hit = p.input.dscp == match.Value[0]
	case consts.MatchType_Fallback:
		hit = true
	default:
		return predicateMiss, fmt.Errorf("unknown match type: %v", match.Type)
	}
	if hit {
		return predicateMatch, nil
	}
	return predicateMiss, nil
}
