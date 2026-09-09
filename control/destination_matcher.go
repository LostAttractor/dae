// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const (
	captureHTTP        uint8 = 1
	captureDestination uint8 = 2
	captureHTTPRequest uint8 = 4
)

// UDP lifetimes retain their predicate program across reloads and client-set
// updates, without retaining the old plane through the outbound callback.
func (m *RoutingMatcher) snapshotDestinations() *RoutingMatcher {
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	return &RoutingMatcher{
		destination:   m.destination,
		matches:       m.matches,
		lpmMatcher:    slices.Clone(m.lpmMatcher),
		domainMatcher: m.domainMatcher,
		rulesMu:       new(sync.RWMutex),
	}
}

func (m *RoutingMatcher) matchDestination(p *RouteParam) (netip.AddrPort, error) {
	if m == nil || len(m.destination.predicates) == 0 {
		return netip.AddrPort{}, nil
	}
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	input := p.routingInput(p.Domain, p.Dest)
	for _, entry := range m.destination.predicates {
		// In an AND-only predicate, an unknown domain (including !domain)
		// can never prove the rule true once bounded sniffing has completed.
		if entry.domain && p.Domain == "" {
			continue
		}
		result, err := m.evaluateRange(entry.start, entry.end, input)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if !result.matched {
			continue
		}
		return netip.AddrPortFrom(entry.targets[rand.IntN(len(entry.targets))], p.Dest.Port()), nil
	}
	return netip.AddrPort{}, nil
}

func (p *RouteParam) dialTarget(override bool) string {
	if p.destination.IsValid() {
		return p.destination.String()
	}
	if !override {
		return p.Dest.String()
	}
	if _, _, err := net.SplitHostPort(p.Domain); err == nil {
		return p.Domain
	}
	return net.JoinHostPort(strings.Trim(p.Domain, "[]"), strconv.Itoa(int(p.Dest.Port())))
}

// Dest is the immutable ingress tuple used for destination matching and replies.
// Every later routing predicate observes this effective destination instead.
func (p *RouteParam) effectiveDestination() netip.AddrPort {
	if p.destination.IsValid() {
		return p.destination
	}
	return p.Dest
}
