// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"container/heap"
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
	name      string
	bitmap    []uint32
	addresses map[netip.Addr]*domainPair
	// expiry never exceeds an address deadline. Extensions leave it behind;
	// GC rescans the record once it passes.
	expiry time.Time
	slot   int // 1 + index in DomainRegistry.due; zero when not queued
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
	activityLag   time.Duration // longest delay before connection activity is observed
	evaluatedAt   time.Time
	due           domainExpiry // every record, ordered by expiry
	gcCount       uint64
	generation    uint64
	activity      *domainActivity
	activityBatch domainActivityBatch // reusable drain buffers, owned by mu

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
func newDomainRegistry(kernelMax int, window time.Duration, update domainMapUpdate, remove func(netip.Addr) error) *DomainRegistry {
	g := &DomainRegistry{
		byName: make(map[string]*domainRecord), byIP: make(map[netip.Addr]*ipRecord), window: window,
		kernel: domainProjection{max: kernelMax, resident: make(map[netip.Addr]domainBitmaps), desired: make(map[netip.Addr]domainBitmaps), pending: make(map[netip.Addr]domainPublication), update: update, remove: remove},
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

type domainObservation struct {
	name   string
	ips    []netip.Addr
	bitmap []uint32
	ttl    int
}

// ObserveDNS records one response as it is delivered, including replay.
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
				r = &domainRecord{name: observation.name, bitmap: slices.Clone(observation.bitmap), addresses: make(map[netip.Addr]*domainPair)}
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
		g.generation++
		if !domainBitmapAllZero(r.bitmap) && deadline.After(s.priority) {
			s.priority = deadline
			return true
		}
	}
	return false
}

// Insertions lower the record's expiry immediately so no deadline is missed.
func (g *DomainRegistry) addPair(r *domainRecord, ip netip.Addr, pair *domainPair) {
	g.indexPair(r, ip, pair)
	if r.slot == 0 {
		r.expiry = pair.retainUntil
		heap.Push(&g.due, r)
	} else if pair.retainUntil.Before(r.expiry) {
		r.expiry = pair.retainUntil
		heap.Fix(&g.due, r.slot-1)
	}
}

func (g *DomainRegistry) indexPair(r *domainRecord, ip netip.Addr, pair *domainPair) {
	s := g.byIP[ip]
	if s == nil {
		s = &ipRecord{domains: make(map[*domainRecord]*domainPair), bump: make([]uint32, domainBitmapWords()), routing: make([]uint32, domainBitmapWords())}
		g.byIP[ip] = s
	}
	r.addresses[ip], s.domains[r] = pair, pair
}

func (g *DomainRegistry) removePair(r *domainRecord, ip netip.Addr) {
	delete(r.addresses, ip)
	s := g.byIP[ip]
	delete(s.domains, r)
	if len(s.domains) == 0 {
		delete(g.byIP, ip)
	}
}

type DomainVerification struct {
	Registered bool // evidence exists in the destination's address family
	Paired     bool
}

// Verify is read-only. A capacity-evicted pair remains evidence until GC.
func (g *DomainRegistry) Verify(name string, ip netip.Addr) (result DomainVerification) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.verifyLocked(name, ip.Unmap())
}

func (g *DomainRegistry) verifyLocked(name string, ip netip.Addr) (result DomainVerification) {
	r := g.byName[name]
	if r == nil {
		return result
	}
	if _, paired := r.addresses[ip]; paired {
		return DomainVerification{Registered: true, Paired: true}
	}
	for addr := range r.addresses {
		if addr.Is4() == ip.Is4() {
			result.Registered = true
			break
		}
	}
	return result
}

// gc keeps a pair for activityLag past its deadline, so activity that happened
// before the deadline but is observed late can still renew it. Only records
// whose expiry has passed are visited; each visit recomputes the exact bound.
func (g *DomainRegistry) gc(now time.Time) map[netip.Addr]struct{} {
	cutoff := now.Add(-g.activityLag)
	var changed map[netip.Addr]struct{}
	for len(g.due) != 0 && !g.due[0].expiry.After(cutoff) {
		r := g.due[0]
		first := true
		for ip, pair := range r.addresses {
			deadline := pair.retainUntil
			if !deadline.After(cutoff) {
				g.removePair(r, ip)
				g.gcCount++
				g.generation++
				if changed == nil {
					changed = make(map[netip.Addr]struct{})
				}
				changed[ip] = struct{}{}
			} else if first || deadline.Before(r.expiry) {
				r.expiry, first = deadline, false
			}
		}
		if len(r.addresses) == 0 {
			heap.Pop(&g.due)
			delete(g.byName, r.name)
		} else {
			heap.Fix(&g.due, 0)
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
	KernelPending    int
}

// Usage takes one coherent snapshot without collecting or refreshing evidence.
func (g *DomainRegistry) Usage() RegistryUsage {
	g.mu.Lock()
	defer g.mu.Unlock()
	usage := RegistryUsage{
		Domains: len(g.byName), IPs: len(g.byIP), GC: g.gcCount,
		KernelUsed: len(g.kernel.resident), KernelMax: g.kernel.max,
		KernelPending: len(g.kernel.pending),
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

// domainExpiry is a container/heap of records keyed by expiry. A record's slot
// is one past its index, so a zero record is safely outside the heap.
type domainExpiry []*domainRecord

func (h domainExpiry) Len() int           { return len(h) }
func (h domainExpiry) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }
func (h domainExpiry) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].slot, h[j].slot = i+1, j+1
}
func (h *domainExpiry) Push(x any) {
	r := x.(*domainRecord)
	*h = append(*h, r)
	r.slot = len(*h)
}
func (h *domainExpiry) Pop() any {
	old := *h
	r := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	r.slot = 0
	return r
}
