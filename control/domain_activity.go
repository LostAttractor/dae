// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"

	dns "github.com/miekg/dns"
)

type domainActivityKey struct {
	ip     netip.Addr
	domain string
}

const domainActivityShards = 32

var domainActivitySeed = maphash.MakeSeed()

type domainActivityBatch [domainActivityShards]map[domainActivityKey]time.Time

// Connections retain this handle, not a control plane or rule matcher. A reload
// moves its destination under the queue lock. This lock is never held while
// waiting for the registry or applying observations / writing kernel maps.
type domainActivity struct {
	shards   [domainActivityShards]sync.Mutex
	registry *DomainRegistry
	pending  domainActivityBatch
}

// Lifecycle transitions acquire all shards in a fixed order. Packet I/O takes
// only its destination's shard; kernel publication never holds these locks.
func (a *domainActivity) lock() {
	for i := range a.shards {
		a.shards[i].Lock()
	}
}

func (a *domainActivity) unlock() {
	for i := len(a.shards) - 1; i >= 0; i-- {
		a.shards[i].Unlock()
	}
}

func newDomainActivityKey(ip netip.Addr, domain string) domainActivityKey {
	ip = ip.Unmap()
	if domain != "" {
		// Literal authorities are not sniffed domains.
		if _, err := netip.ParseAddr(domain); err == nil {
			domain = ""
		} else {
			domain = dns.CanonicalName(domain)
		}
	}
	return domainActivityKey{ip, domain}
}

// enqueue records the latest observation per key. The original timestamp is
// retained even if the worker is busy. Membership-changing operations drain
// earlier observations before changing evidence, including unknown-key events.
// Keys come from valid original flow destinations; nil handles disable observing.
func (a *domainActivity) enqueue(key domainActivityKey, at time.Time) *DomainRegistry {
	return a.enqueueShard(key, maphash.Comparable(domainActivitySeed, key)%domainActivityShards, at)
}

func (a *domainActivity) enqueueShard(key domainActivityKey, shard uint64, at time.Time) *DomainRegistry {
	if a == nil {
		return nil
	}
	a.shards[shard].Lock()
	defer a.shards[shard].Unlock()
	g := a.registry
	// Runtime redirects the owner before retiring a generation. Only terminal
	// closure clears it, so a retained connection has no observation gap.
	if g == nil {
		return nil
	}
	pending := a.pending[shard]
	if pending == nil {
		pending = make(map[domainActivityKey]time.Time)
		a.pending[shard] = pending
	}
	if at.After(pending[key]) {
		pending[key] = at
	}
	return g
}

// Initial attempts remain synchronous, after their first routing decision.
// A concurrent reload drains this event into the old or the new registry.
func (a *domainActivity) observe(ip netip.Addr, domain string, at time.Time) {
	if g := a.enqueue(newDomainActivityKey(ip, domain), at); g != nil {
		g.flushActivity()
	}
}

func (g *DomainRegistry) flushActivity() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		reconsider := g.drainActivity()
		g.syncProjection(g.gc(g.evaluatedAt), reconsider, g.evaluatedAt)
	}
}

// All callers own g.mu. Swap reusable maps under the queue lock, then release
// it before visiting pairs. Enqueues after this boundary belong to the next
// batch; they can proceed while this operation updates registry membership.
func (g *DomainRegistry) drainActivity() bool {
	a := g.activity
	a.lock()
	if a.registry != g {
		a.unlock()
		return false
	}
	a.pending, g.activityBatch = g.activityBatch, a.pending
	a.unlock()
	return g.applyActivity()
}

func (g *DomainRegistry) applyActivity() bool {
	reconsider := false
	for _, batch := range g.activityBatch {
		for key, at := range batch {
			g.clock(at)
			if g.touch(key, at) {
				if _, resident := g.kernel.resident[key.ip]; !resident {
					reconsider = true
				}
			}
		}
		clear(batch)
	}
	return reconsider
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
