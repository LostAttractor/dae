// SPDX-License-Identifier: AGPL-3.0-only

// Package mitmverify verifies transparent MITM using virtual HTTPS destinations
// answered locally by the interception plugin, without an upstream service.
package mitmverify

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

const InstanceID = "dae-mitm-test"

const DefaultIPv4 = "203.0.113.254"
const DefaultIPv6 = "2001:db8:ffff::254"

const testLifetime = time.Minute
const maxTests = 256
const maxTestsPerDevice = 8

type challenge struct {
	api.MITMTest
	ip     netip.Addr
	mac    [6]byte
	mitm   netip.AddrPort
	origin string
}

type Service struct {
	generation  string
	fingerprint string
	targets     [2]netip.Addr
	mu          sync.Mutex
	tests       map[string]*challenge
}

func ParseTargets(ip4, ip6 string) ([2]netip.Addr, error) {
	if ip4 == "" {
		ip4 = DefaultIPv4
	}
	if ip6 == "" {
		ip6 = DefaultIPv6
	}
	var targets [2]netip.Addr
	for i, text := range []string{ip4, ip6} {
		ip, err := netip.ParseAddr(text)
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.Is4In6() || ip.Is4() != (i == 0) {
			return targets, fmt.Errorf("api_mitm_test_ipv%d requires a unicast IPv%d literal", 4+i*2, 4+i*2)
		}
		targets[i] = ip
	}
	return targets, nil
}

func New(fingerprint string, targets [2]netip.Addr, addresses []net.Addr) (*Service, error) {
	s := &Service{generation: rand.Text(), fingerprint: fingerprint, targets: targets,
		tests: make(map[string]*challenge)}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		for _, target := range targets {
			if prefix.Contains(target) {
				return nil, fmt.Errorf("MITM test target %s overlaps local subnet %s; select an unused routed address with api_mitm_test_ipv4/api_mitm_test_ipv6", target, prefix)
			}
		}
	}
	return s, nil
}

func (s *Service) Generation() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// Invalidate also handles publication of a retained host (for example suspend).
func (s *Service) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.tests)
	s.generation = rand.Text()
}
func (s *Service) Targets() []netip.AddrPort {
	return []netip.AddrPort{netip.AddrPortFrom(s.targets[0], 443), netip.AddrPortFrom(s.targets[1], 443)}
}

func (s *Service) Origins() []string {
	return []string{httpsOrigin(netip.AddrPortFrom(s.targets[0], 443)), httpsOrigin(netip.AddrPortFrom(s.targets[1], 443))}
}

func httpsOrigin(target netip.AddrPort) string {
	address := target.String()
	if target.Port() == 443 {
		address = strings.TrimSuffix(address, ":443")
	}
	return "https://" + address
}

func (s *Service) Plan() plugin.Plan {
	scope := make(plugin.Scope, 0, len(s.targets))
	for _, host := range s.targets {
		scope = append(scope, plugin.HostRule{Host: host.String(), Ports: []uint16{443}})
	}
	return plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: scope}}}
}

func (s *Service) prune(now time.Time) {
	for id, test := range s.tests {
		if !now.Before(test.ExpiresAt) {
			delete(s.tests, id)
		}
	}
}

func (s *Service) Start(ip netip.Addr, mac [6]byte, local netip.AddrPort, origin string, enabled bool) (api.MITMTest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.prune(now)
	retained := 0
	for _, test := range s.tests {
		if test.mac == mac {
			retained++
		}
	}
	if retained >= maxTestsPerDevice || len(s.tests) >= maxTests {
		return api.MITMTest{}, fmt.Errorf("too many MITM tests; retry in one minute")
	}
	id := rand.Text()
	host := local.Addr().Unmap()
	target := s.targets[0]
	if host.Is6() {
		target = s.targets[1]
	}
	intercept := netip.AddrPortFrom(target, 443)
	test := &challenge{
		ID: id, CAFingerprint: s.fingerprint,
		StartedAt: now, ExpiresAt: now.Add(testLifetime),
		MITMURL: httpsOrigin(intercept) + "/test/" + id, MITMEnabled: enabled,
		ip: ip.Unmap(), mac: mac, mitm: intercept, origin: origin,
	}
	s.tests[id] = test
	return test.MITMTest, nil
}

func (s *Service) Get(id string, ip netip.Addr, mac [6]byte) (api.MITMTest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	test := s.tests[id]
	if test == nil || test.ip != ip.Unmap() || test.mac != mac {
		return api.MITMTest{}, false
	}
	return test.MITMTest, true
}
