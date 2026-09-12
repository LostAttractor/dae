// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sync"
	"time"

	dns "github.com/miekg/dns"
)

type domainActivityKey struct {
	ip     netip.Addr
	domain string
}

type domainActivityEvent struct {
	key domainActivityKey
	at  time.Time
}

// Connections retain this handle, not a control plane or rule matcher. A reload
// moves its destination under the same lock used by observations.
type domainActivity struct {
	mu       sync.Mutex
	registry *DomainRegistry
	handoff  bool
	pending  []domainActivityEvent
}

func (a *domainActivity) prepareHandoff() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handoff = true
}

func (a *domainActivity) observe(ip netip.Addr, domain string, at time.Time) {
	if a == nil || !ip.IsValid() {
		return
	}
	ip = ip.Unmap()
	if domain != "" {
		// Literal authorities are not sniffed domains.
		if _, err := netip.ParseAddr(domain); err == nil {
			domain = ""
		} else {
			domain = dns.CanonicalName(domain)
		}
	}
	key := domainActivityKey{ip, domain}
	a.mu.Lock()
	defer a.mu.Unlock()
	g := a.registry
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		if a.handoff {
			a.pending = append(a.pending, domainActivityEvent{key, at})
		}
		return
	}
	now := g.clock(at)
	reconsider := g.touch(key, at)
	if _, resident := g.kernel.resident[ip]; resident {
		reconsider = false
	}
	g.syncProjection(g.gc(now), reconsider, now)
}

func (g *DomainRegistry) touch(key domainActivityKey, at time.Time) bool {
	deadline := at.Add(g.window)
	if key.domain != "" {
		if r := g.byName[key.domain]; r != nil {
			if pair := r.addresses[key.ip]; pair != nil {
				return g.extend(r, g.byIP[key.ip], pair, deadline)
			}
		}
		return false
	}
	s := g.byIP[key.ip]
	if s == nil {
		return false
	}
	reconsider := false
	for r, pair := range s.domains {
		if g.extend(r, s, pair, deadline) {
			reconsider = true
		}
	}
	return reconsider
}

func (c *ControlPlane) domainActivity() *domainActivity {
	if c.core == nil || c.core.domainRegistry == nil {
		return nil
	}
	return c.core.domainRegistry.activity
}
