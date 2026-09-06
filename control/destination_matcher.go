// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

const (
	captureHTTP        uint8 = 1
	captureDestination uint8 = 2
)

// Each predicate has ordinary logical edges and boolean true/false terminals.
// Its action lives here, not in the kernel outbound ID namespace.
type destinationPredicate struct {
	start, end int
	domain     bool
	rule       routing.DestinationRewrite
}

type destinationDecision struct {
	matched bool
	target  netip.AddrPort
	proxy   bool
}

func (d destinationDecision) applies(direct bool) bool {
	return d.matched && (direct || d.proxy)
}

func (m *RoutingMatcher) matchDestination(p *RouteParam) (destinationDecision, error) {
	if m == nil || len(m.destinations) == 0 {
		return destinationDecision{}, nil
	}
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	source, destination := p.Src.Addr().As16(), p.Dest.Addr().As16()
	var mac [16]byte
	copy(mac[10:], p.routingResult.Mac[:])
	proto := p.networkType.L4Proto.ToL4ProtoType()
	if p.routingResult.Protocol != 0 {
		proto = consts.L4ProtoType(p.routingResult.Protocol)
	}
	input := routingInput{
		sourceAddr:  source[:],
		destAddr:    destination[:],
		sourcePort:  p.Src.Port(),
		destPort:    p.Dest.Port(),
		ipVersion:   p.networkType.IpVersion.ToIpVersionType(),
		l4proto:     proto,
		domain:      p.Domain,
		processName: p.routingResult.Pname,
		ifindex:     p.routingResult.Ifindex,
		tos:         p.routingResult.Dscp,
		mac:         mac[:],
	}
	for _, entry := range m.destinations {
		// In an AND-only predicate, an unknown domain (including !domain)
		// can never prove the rule true once bounded sniffing has completed.
		if entry.domain && p.Domain == "" {
			continue
		}
		result, _, _, err := m.matchRange(entry.start, entry.end, input)
		if err != nil {
			return destinationDecision{}, err
		}
		if result != consts.OutboundDirect {
			continue
		}
		decision := destinationDecision{matched: true, proxy: entry.rule.Proxy, target: p.Dest}
		decision.target = netip.AddrPortFrom(entry.rule.To[rand.IntN(len(entry.rule.To))], p.Dest.Port())
		return decision, nil
	}
	return destinationDecision{}, nil
}

func (p *RouteParam) dialTarget(outbound consts.OutboundIndex, override bool) string {
	d := p.destination
	if outbound != consts.OutboundBlock && d.matched && (outbound == consts.OutboundDirect || d.proxy) {
		return d.target.String()
	}
	if !override {
		return p.Dest.String()
	}
	if _, _, err := net.SplitHostPort(p.Domain); err == nil {
		return p.Domain
	}
	return net.JoinHostPort(strings.Trim(p.Domain, "[]"), strconv.Itoa(int(p.Dest.Port())))
}
