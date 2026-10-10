// SPDX-License-Identifier: AGPL-3.0-only

// Package certtest provides browser challenges using the API's direct TLS branch
// and virtual HTTPS destinations answered locally by the interception plugin.
package certtest

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	mitmca "github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
)

const InstanceID = "dae-certificate-test"

const DefaultIPv4 = "203.0.113.254"
const DefaultIPv6 = "2001:db8:ffff::254"

const testLifetime = time.Minute
const maxTests = 256

type challenge struct {
	api.CertificateTest
	ip     netip.Addr
	mac    [6]byte
	trust  netip.AddrPort
	mitm   netip.AddrPort
	origin string
}

type Service struct {
	generation string
	authority  *mitmca.Authority
	apiPort    uint16
	targets    [2]netip.Addr
	hosts      []netip.Addr
	mu         sync.Mutex
	tests      map[string]*challenge
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

func New(authority *mitmca.Authority, apiPort uint16, targets [2]netip.Addr, addresses []net.Addr) (*Service, error) {
	s := &Service{generation: rand.Text(), authority: authority, apiPort: apiPort, targets: targets,
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
		ip := prefix.Addr().Unmap()
		if (ip.IsGlobalUnicast() || ip.IsLoopback()) && !slices.Contains(s.hosts, ip) {
			s.hosts = append(s.hosts, ip)
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

func (s *Service) Start(ip netip.Addr, mac [6]byte, local netip.AddrPort, enabled bool) (api.CertificateTest, error) {
	if local.Port() != s.apiPort || !slices.Contains(s.hosts, local.Addr().Unmap()) {
		return api.CertificateTest{}, fmt.Errorf("certificate tests require a current local IPv4 or non-link-local IPv6 address; reload after changing router addresses")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.prune(now)
	if len(s.tests) >= maxTests {
		return api.CertificateTest{}, fmt.Errorf("too many certificate tests; retry in one minute")
	}
	id := rand.Text()
	host := local.Addr().Unmap()
	local = netip.AddrPortFrom(host, local.Port())
	origin := "http://" + local.String()
	if local.Port() == 80 {
		origin = "http://" + strings.TrimSuffix(local.String(), ":80")
	}
	target := s.targets[0]
	if host.Is6() {
		target = s.targets[1]
	}
	intercept := netip.AddrPortFrom(target, 443)
	test := &challenge{
		ID: id, CAFingerprint: s.authority.Fingerprint(),
		StartedAt: now, ExpiresAt: now.Add(testLifetime),
		TrustURL: httpsOrigin(local) + "/test/" + id, MITMURL: httpsOrigin(intercept) + "/test/" + id, MITMEnabled: enabled,
		ip: ip.Unmap(), mac: mac, trust: local, mitm: intercept, origin: origin,
	}
	s.tests[id] = test
	return test.CertificateTest, nil
}

func (s *Service) Get(id string, ip netip.Addr, mac [6]byte) (api.CertificateTest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	test := s.tests[id]
	if test == nil || test.ip != ip.Unmap() || test.mac != mac {
		return api.CertificateTest{}, false
	}
	return test.CertificateTest, true
}
