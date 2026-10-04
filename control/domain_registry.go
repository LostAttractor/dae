// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Both indexes point to the same pair. Activity can extend its deadline, never
// create evidence. Rule bitmaps belong to domains, not individual pairs.
type domainPair struct {
	retainUntil time.Time
}

type domainRecord struct {
	bitmap    []uint32
	addresses map[netip.Addr]*domainPair
}

type ipRecord struct {
	domains  map[*domainRecord]*domainPair
	bump     []uint32
	routing  []uint32
	priority time.Time
}

// DomainRegistry owns domain-IP evidence with two lookup directions. Kernel
// eviction only changes projection membership, never userspace evidence.
type DomainRegistry struct {
	mu            sync.Mutex
	byName        map[string]*domainRecord
	byIP          map[netip.Addr]*ipRecord
	kernel        domainProjection
	window        time.Duration
	evaluatedAt   time.Time
	nextGC        time.Time // lower bound on pair deadlines; zero when empty
	gcCount       uint64
	generation    uint64
	activity      *domainActivity
	activityBatch map[domainActivityKey]time.Time // reusable drain buffer, owned by mu

	closed     bool
	stopCh     chan struct{}
	stopOnce   sync.Once
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
		byName: make(map[string]*domainRecord), byIP: make(map[netip.Addr]*ipRecord), window: window,
		kernel: domainProjection{max: kernelMax, resident: make(map[netip.Addr]struct{}), update: update, remove: remove},
		stopCh: make(chan struct{}), closeDone: make(chan struct{}), activityBatch: make(map[domainActivityKey]time.Time),
	}
	g.activity = &domainActivity{registry: g, pending: make(map[domainActivityKey]time.Time)}
	return g
}

func (g *DomainRegistry) clock(now time.Time) time.Time {
	if now.After(g.evaluatedAt) {
		g.evaluatedAt = now
	}
	return g.evaluatedAt
}

type domainObservation struct {
	name   string
	ips    []netip.Addr
	bitmap []uint32
	ttl    int
}

// ObserveDNS records one successfully delivered response, including replay.
// A delayed observation retains its own timestamp; the clock prevents it from
// reviving evidence already collected after a newer observation.
func (g *DomainRegistry) ObserveDNS(observations []domainObservation, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	reconsider := g.drainActivity()
	now := g.clock(at)
	changed := g.gc(now)
	for _, observation := range observations {
		deadline := at.Add(max(time.Duration(observation.ttl)*time.Second, g.window))
		if !deadline.After(now) {
			continue
		}
		for _, ip := range observation.ips {
			ip = ip.Unmap()
			r := g.byName[observation.name]
			if r == nil {
				r = &domainRecord{bitmap: slices.Clone(observation.bitmap), addresses: make(map[netip.Addr]*domainPair)}
				g.byName[observation.name] = r
			}
			if pair := r.addresses[ip]; pair != nil {
				if g.extend(r, g.byIP[ip], pair, deadline) {
					if _, resident := g.kernel.resident[ip]; !resident {
						reconsider = true
					}
				}
			} else {
				g.addPair(r, ip, &domainPair{retainUntil: deadline})
				g.generation++
				if changed == nil {
					changed = make(map[netip.Addr]struct{})
				}
				changed[ip] = struct{}{}
			}
		}
	}
	g.syncProjection(changed, reconsider, now)
}

// extend returns whether this IP's relevant priority increased. Membership and
// bitmaps are unchanged; a resident IP cannot lose its slot by ranking higher.
func (g *DomainRegistry) extend(r *domainRecord, s *ipRecord, pair *domainPair, deadline time.Time) bool {
	if deadline.After(pair.retainUntil) {
		pair.retainUntil = deadline
		g.trackDeadline(deadline)
		g.generation++
		if !domainBitmapAllZero(r.bitmap) && deadline.After(s.priority) {
			s.priority = deadline
			return true
		}
	}
	return false
}

func (g *DomainRegistry) addPair(r *domainRecord, ip netip.Addr, pair *domainPair) {
	s := g.byIP[ip]
	if s == nil {
		s = &ipRecord{domains: make(map[*domainRecord]*domainPair), bump: make([]uint32, domainBitmapWords()), routing: make([]uint32, domainBitmapWords())}
		g.byIP[ip] = s
	}
	r.addresses[ip], s.domains[r] = pair, pair
	g.trackDeadline(pair.retainUntil)
}

func (g *DomainRegistry) removePair(r *domainRecord, ip netip.Addr) {
	delete(r.addresses, ip)
	s := g.byIP[ip]
	delete(s.domains, r)
	if len(s.domains) == 0 {
		delete(g.byIP, ip)
	}
}

// Extensions may leave an earlier bound behind. The next scan recomputes it;
// insertions must lower it immediately so no deadline can be missed.
func (g *DomainRegistry) trackDeadline(deadline time.Time) {
	if g.nextGC.IsZero() || deadline.Before(g.nextGC) {
		g.nextGC = deadline
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
		_, resident := g.kernel.resident[ip]
		return DomainVerification{true, true, resident || domainBitmapAllZero(r.bitmap)}
	}
	for addr := range r.addresses {
		if addr.Is4() == ip.Is4() {
			result.Registered = true
			break
		}
	}
	return result
}

func (g *DomainRegistry) gc(now time.Time) map[netip.Addr]struct{} {
	if g.nextGC.IsZero() || now.Before(g.nextGC) {
		return nil
	}
	var changed map[netip.Addr]struct{}
	g.nextGC = time.Time{}
	for name, r := range g.byName {
		for ip, pair := range r.addresses {
			deadline := pair.retainUntil
			if !deadline.After(now) {
				g.removePair(r, ip)
				g.gcCount++
				g.generation++
				if changed == nil {
					changed = make(map[netip.Addr]struct{})
				}
				changed[ip] = struct{}{}
			} else {
				g.trackDeadline(deadline)
			}
		}
		if len(r.addresses) == 0 {
			delete(g.byName, name)
		}
	}
	return changed
}

func (g *DomainRegistry) Sweep(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	reconsider := g.drainActivity()
	now = g.clock(now)
	g.syncProjection(g.gc(now), reconsider, now)
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
func (g *DomainRegistry) Usage() RegistryUsage {
	g.mu.Lock()
	defer g.mu.Unlock()
	usage := RegistryUsage{
		Domains: len(g.byName), IPs: len(g.byIP), GC: g.gcCount,
		KernelUsed: len(g.kernel.resident), KernelMax: g.kernel.max,
	}
	for _, r := range g.byName {
		usage.UserUsed += len(r.addresses)
	}
	for ip, s := range g.byIP {
		if !domainBitmapAllZero(s.bump) {
			usage.KernelCandidates++
		}
		if ip.Is4() {
			usage.IPv4++
		} else {
			usage.IPv6++
		}
	}
	return usage
}
