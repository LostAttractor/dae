// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"hash/maphash"
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
		defaultProfileID: m.defaultProfileID,
		profiles:         m.profiles,
		destinations:     m.destinations,
		matches:          m.matches,
		lpmMatcher:       slices.Clone(m.lpmMatcher),
		domainMatcher:    m.domainMatcher,
		rulesMu:          new(sync.RWMutex),
	}
}

func (m *RoutingMatcher) destinationProgram(profileID uint32) DestinationProgram {
	if profileID == 0 {
		profileID = m.defaultProfileID
	}
	return m.destinations[profileID]
}

func (m *RoutingMatcher) matchDestination(p *RouteParam) (netip.AddrPort, error) {
	if m == nil {
		return netip.AddrPort{}, nil
	}
	profileID := p.routingResult.ProfileId
	if profileID == 0 {
		profileID = m.defaultProfileID
	}
	if _, ok := m.profiles[profileID]; !ok {
		return netip.AddrPort{}, fmt.Errorf("unknown routing profile %d", profileID)
	}
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	input := p.routingInput(p.Domain, p.Dest)
	for index, entry := range m.destinationProgram(profileID).predicates {
		// In an AND-only predicate, an unknown domain (including !domain)
		// can never prove the rule true once bounded sniffing has completed.
		if entry.domain && p.Domain == "" {
			continue
		}
		result, err := m.evaluateSpans([]routingSpan{entry.span}, input)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if !result.matched {
			continue
		}
		port := entry.port
		if port == 0 {
			port = p.Dest.Port()
		}
		selected := 0
		if p.destinationSeed != nil {
			key := struct {
				Destination netip.AddrPort
				Profile     uint32
				Rule        int
			}{p.Dest, profileID, index}
			selected = int(maphash.Comparable(*p.destinationSeed, key) % uint64(len(entry.targets)))
		} else {
			selected = rand.IntN(len(entry.targets))
		}
		return netip.AddrPortFrom(entry.targets[selected], port), nil
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
