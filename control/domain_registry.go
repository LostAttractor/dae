// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// A domain owns one rule bitmap and an independent GC deadline for each IP.
// Evidence is historical: activity may extend an existing pair, never create it.
type domainRecord struct {
	bitmap    []uint32
	addresses map[netip.Addr]time.Time
}

// DomainRegistry keeps one userspace index. The bounded kernel projection is
// derived from it; kernel eviction never removes userspace evidence.
type DomainRegistry struct {
	mu          sync.Mutex
	byName      map[string]*domainRecord
	kernel      domainProjection
	window      time.Duration
	evaluatedAt time.Time
	gcCount     uint64
	generation  uint64
	activity    *domainActivity
	adopted     bool

	closed     bool
	stopCh     chan struct{}
	workerDone chan struct{}
	closeDone  chan struct{}

	// diskMu serializes snapshot writers; the remaining fields use mu.
	diskMu          sync.Mutex
	diskPath        string
	savedGeneration uint64
}

// Callers provide the actual map capacity and both kernel writers. Domain
// bitmaps have the width produced by the current compiled matcher. The
// constructor does not start background work.
func newDomainRegistry(kernelMax int, window time.Duration, update domainMapUpdate, remove func(netip.Addr)) *DomainRegistry {
	g := &DomainRegistry{
		byName: make(map[string]*domainRecord), window: window,
		kernel: domainProjection{max: kernelMax, resident: make(map[netip.Addr]*ipKernelState), update: update, remove: remove},
		stopCh: make(chan struct{}), closeDone: make(chan struct{}),
	}
	g.activity = &domainActivity{registry: g}
	return g
}

func (g *DomainRegistry) clock(now time.Time) time.Time {
	if now.After(g.evaluatedAt) {
		g.evaluatedAt = now
	}
	return g.evaluatedAt
}

// ObserveDNS records evidence at successful client delivery, including replay.
// A delayed observation retains its own timestamp; the clock prevents it from
// reviving evidence already collected after a newer observation.
func (g *DomainRegistry) ObserveDNS(name string, ip netip.Addr, bitmap []uint32, ttl int, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	now := g.clock(at)
	g.gc(now)
	deadline := at.Add(max(time.Duration(ttl)*time.Second, g.window))
	if deadline.After(now) {
		r := g.byName[name]
		if r == nil {
			r = &domainRecord{bitmap: slices.Clone(bitmap), addresses: make(map[netip.Addr]time.Time)}
			g.byName[name] = r
		}
		g.extend(r, ip.Unmap(), deadline)
	}
	g.kernel.reconcile(g.byName, now)
}

func (g *DomainRegistry) extend(r *domainRecord, ip netip.Addr, deadline time.Time) {
	if deadline.After(r.addresses[ip]) {
		r.addresses[ip] = deadline
		g.generation++
	}
}

type DomainVerification struct {
	Registered    bool // evidence exists in the destination's address family
	Paired        bool
	KernelCovered bool
}

// Verify is read-only. A capacity-evicted pair remains evidence until GC.
func (g *DomainRegistry) Verify(name string, ip netip.Addr) (result DomainVerification) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ip = ip.Unmap()
	r := g.byName[name]
	if r == nil {
		return result
	}
	if _, paired := r.addresses[ip]; paired {
		return DomainVerification{true, true, g.kernel.resident[ip] != nil || domainBitmapAllZero(r.bitmap)}
	}
	for addr := range r.addresses {
		if addr.Is4() == ip.Is4() {
			result.Registered = true
			break
		}
	}
	return result
}

func (g *DomainRegistry) gc(now time.Time) {
	for name, r := range g.byName {
		for ip, deadline := range r.addresses {
			if !deadline.After(now) {
				delete(r.addresses, ip)
				g.gcCount++
				g.generation++
			}
		}
		if len(r.addresses) == 0 {
			delete(g.byName, name)
		}
	}
}

func (g *DomainRegistry) Sweep(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	now = g.clock(now)
	g.gc(now)
	g.kernel.reconcile(g.byName, now)
}

type RegistryUsage struct {
	UserUsed         int // retained domain-IP pairs
	Domains          int
	IPs              int // distinct across all domains
	IPv4             int
	IPv6             int
	GC               uint64
	KernelUsed       int
	KernelMax        int
	KernelCandidates int
}

// Usage takes one coherent snapshot without collecting or refreshing evidence.
// Its temporary deduplication set is not maintained on the observation path.
func (g *DomainRegistry) Usage() RegistryUsage {
	g.mu.Lock()
	defer g.mu.Unlock()
	usage := RegistryUsage{
		Domains: len(g.byName), GC: g.gcCount,
		KernelUsed: len(g.kernel.resident), KernelMax: g.kernel.max, KernelCandidates: g.kernel.candidates,
	}
	// Count from the evidence index only when status is requested. Shared IPs
	// count once regardless of domain count or kernel residency.
	ips := make(map[netip.Addr]struct{})
	for _, r := range g.byName {
		usage.UserUsed += len(r.addresses)
		for ip := range r.addresses {
			ips[ip] = struct{}{}
		}
	}
	usage.IPs = len(ips)
	for ip := range ips {
		if ip.Is4() {
			usage.IPv4++
		} else {
			usage.IPv6++
		}
	}
	return usage
}
