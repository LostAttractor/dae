// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"container/heap"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// Both indexes point to the same pair. Activity can extend its deadline, never
// create evidence. Rule bitmaps belong to domains, not individual pairs.
type domainPair struct {
	retainUntil time.Time
	ordinal     uint32 // position in the persisted baseline and journal
	listed      uint32 // persistence renewal window that last listed this pair
}

type domainRecord struct {
	name        string
	bitmap      []uint32
	addresses   map[netip.Addr]*domainPair
	addressPeak int
	// expiry never exceeds an address deadline. Extensions leave it behind;
	// GC rescans the record once it passes.
	expiry time.Time
	slot   int // 1 + index in DomainRegistry.due; zero when not queued
}

type ipRecord struct {
	domains    map[*domainRecord]*domainPair
	domainPeak int
	matched    int // members with a nonzero rule bitmap
	bump       []uint32
	routing    []uint32
	priority   time.Time
}

// DomainRegistry owns domain-IP evidence with two lookup directions. Kernel
// eviction only changes projection membership, never userspace evidence.
type DomainRegistry struct {
	domainCapacity
	mu            sync.Mutex
	byName        map[string]*domainRecord
	byIP          map[netip.Addr]*ipRecord
	pairs         int
	ipv4          int
	kernel        domainProjection
	direct        domainDirectSource
	directSlots   map[netip.Addr]domainDirectSlot // confirmed installations and last consumed stamps
	directRetry   map[netip.Addr]uint64           // failed writes: desired or still installed
	directSerial  uint64
	directWarning time.Time
	window        time.Duration
	activityLag   time.Duration // longest delay before connection activity is observed
	evaluatedAt   time.Time
	due           domainExpiry // every record, ordered by expiry
	gcCount       uint64
	activity      *domainActivity
	activityBatch domainActivityBatch // reusable drain buffers, owned by mu
	persist       *domainLog          // nil unless this registry owns the files
	persistWake   chan struct{}       // asks the worker for writes mutations left to it

	closed     bool
	stopCh     chan struct{}
	stopOnce   sync.Once
	workerDone chan struct{}
	closeDone  chan struct{}
}

// Callers provide the actual map capacity and both kernel writers. Domain
// bitmaps have the width produced by the current compiled matcher. The
// constructor does not start background work.
func newDomainRegistry(kernelMax int, window time.Duration, update domainMapUpdate, remove func(netip.Addr) error) *DomainRegistry {
	g := &DomainRegistry{
		domainCapacity: domainCapacity{memoryLimit: consts.DefaultDNSRegistryMemoryLimit},
		byName:         make(map[string]*domainRecord), byIP: make(map[netip.Addr]*ipRecord), window: window,
		kernel: domainProjection{max: kernelMax, resident: make(map[netip.Addr]domainBitmaps), desired: make(map[netip.Addr]domainBitmaps), pending: make(map[netip.Addr]domainPublication), update: update, remove: remove},
		stopCh: make(chan struct{}), closeDone: make(chan struct{}), persistWake: make(chan struct{}, 1),
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
// reviving evidence already collected after a newer observation. It returns
// the journal append of the new pairs, or nil, for the caller to run once the
// reply is sent. A busy journal writer takes over the queued pairs; otherwise
// the caller writes them outside the registry lock.
func (g *DomainRegistry) ObserveDNS(observations []domainObservation, at time.Time) (journal func()) {
	if l := g.observeDNS(observations, at); l != nil {
		return func() { g.appendNew(l) }
	}
	return nil
}

// observeDNS returns the log that queued new pairs, if any.
func (g *DomainRegistry) observeDNS(observations []domainObservation, at time.Time) (created *domainLog) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	reconsider := g.drainActivity()
	now := g.clock(at)
	changed := g.gc(now)
	for _, observation := range observations {
		deadline := at.Add(max(time.Duration(observation.ttl)*time.Second, g.window))
		if !deadline.After(now) {
			continue
		}
		r := g.byName[observation.name]
		bitmap := observation.bitmap
		if r != nil {
			bitmap = r.bitmap
		} else if domainBitmapAllZero(bitmap) {
			bitmap = nil
		}
		for _, ip := range observation.ips {
			ip = ip.Unmap()
			if r != nil {
				if pair := r.addresses[ip]; pair != nil {
					s := g.byIP[ip]
					if g.extend(r, s, pair, deadline) && g.mayEnterProjection(ip, s.priority) {
						reconsider = true
					}
					continue
				}
			}
			s := g.byIP[ip]
			cost := domainPairIPCost(s != nil, s != nil && s.matched != 0, bitmap != nil)
			if r == nil {
				cost += domainNameMemory(observation.name, bitmap)
			}
			if cost > g.memoryLimit-g.memoryUsed {
				g.omitPair(ip, deadline, now)
				continue
			}
			if r == nil {
				r = &domainRecord{name: observation.name, bitmap: slices.Clone(bitmap), addresses: make(map[netip.Addr]*domainPair)}
				g.byName[observation.name] = r
				g.memoryUsed += domainNameMemory(r.name, r.bitmap)
			}
			pair := &domainPair{retainUntil: deadline}
			g.addPair(r, ip, pair)
			if g.persist != nil {
				g.persist.add(r.name, ip, pair)
				created = g.persist
			}
			if changed == nil {
				changed = make(map[netip.Addr]struct{})
			}
			changed[ip] = struct{}{}
		}
	}
	g.syncProjection(changed, reconsider, now)
	return created
}

// extend returns whether this IP's relevant priority increased. Membership and
// bitmaps are unchanged; a resident IP cannot lose its slot by ranking higher.
func (g *DomainRegistry) extend(r *domainRecord, s *ipRecord, pair *domainPair, deadline time.Time) bool {
	if deadline.After(pair.retainUntil) {
		pair.retainUntil = deadline
		if g.persist != nil {
			g.persist.renew(pair)
		}
		if r.bitmap != nil && deadline.After(s.priority) {
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
		s = &ipRecord{domains: make(map[*domainRecord]*domainPair)}
		g.byIP[ip] = s
		g.memoryUsed += domainIPMemory
		if ip.Is4() {
			g.ipv4++
		}
	}
	r.addresses[ip], s.domains[r] = pair, pair
	r.addressPeak = max(r.addressPeak, len(r.addresses))
	s.domainPeak = max(s.domainPeak, len(s.domains))
	g.pairs++
	g.memoryUsed += domainPairMemory
	if r.bitmap != nil {
		if s.matched == 0 {
			g.memoryUsed += domainIPBitmapMemory()
		}
		s.matched++
	}
}

func (g *DomainRegistry) removePair(r *domainRecord, ip netip.Addr) {
	delete(r.addresses, ip)
	s := g.byIP[ip]
	delete(s.domains, r)
	g.pairs--
	g.memoryUsed -= domainPairMemory
	if r.bitmap != nil {
		s.matched--
		if s.matched == 0 {
			g.memoryUsed -= domainIPBitmapMemory()
		}
	}
	if len(s.domains) == 0 {
		g.memoryUsed -= domainIPMemory
		delete(g.byIP, ip)
		if ip.Is4() {
			g.ipv4--
		}
	}
}

// Go maps retain their backing storage after delete. Rebuild sparse indexes
// from the live count; leave single-group maps and ordinary churn alone.
func trimDomainIndex[K comparable, V any](index map[K]V, peak *int) map[K]V {
	if *peak <= 8 || len(index) > *peak/4 {
		return index
	}
	*peak = len(index)
	live := make(map[K]V, len(index))
	maps.Copy(live, index)
	return live
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
	g.expireIncomplete(cutoff)
	var changed map[netip.Addr]struct{}
	for len(g.due) != 0 && !g.due[0].expiry.After(cutoff) {
		r := g.due[0]
		first := true
		for ip, pair := range r.addresses {
			deadline := pair.retainUntil
			if !deadline.After(cutoff) {
				g.removePair(r, ip)
				g.gcCount++
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
			g.memoryUsed -= domainNameMemory(r.name, r.bitmap)
		} else {
			r.addresses = trimDomainIndex(r.addresses, &r.addressPeak)
			heap.Fix(&g.due, 0)
		}
	}
	for ip := range changed {
		if s := g.byIP[ip]; s != nil {
			s.domains = trimDomainIndex(s.domains, &s.domainPeak)
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
	UserUsed                int // retained domain-IP pairs
	MemoryUsed, MemoryLimit int64
	OmittedPairs            uint64 // new pair observations omitted at capacity, not distinct pairs
	IncompleteBuckets       int
	Domains                 int
	IPs                     int // distinct across all domains
	IPv4                    int
	IPv6                    int
	GC                      uint64
	KernelUsed              int
	KernelMax               int
	KernelCandidates        int
	KernelPending           int
}

// Usage takes one coherent snapshot without collecting or refreshing evidence.
func (g *DomainRegistry) Usage() RegistryUsage {
	g.mu.Lock()
	defer g.mu.Unlock()
	return RegistryUsage{
		UserUsed: g.pairs, IPv4: g.ipv4, IPv6: len(g.byIP) - g.ipv4,
		MemoryUsed: g.memoryUsed, MemoryLimit: g.memoryLimit, OmittedPairs: g.omittedPairs, IncompleteBuckets: g.incompleteCount,
		Domains: len(g.byName), IPs: len(g.byIP), GC: g.gcCount,
		KernelUsed: len(g.kernel.resident), KernelMax: g.kernel.max,
		KernelCandidates: len(g.kernel.desired) + g.kernel.omitted, KernelPending: len(g.kernel.pending),
	}
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
