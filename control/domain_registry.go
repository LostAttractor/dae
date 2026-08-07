/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/heap"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// DomainRegistrySweepInterval is how often the registry reaps expired
// kernel contributions and runs userspace memory-pressure GC. GC also
// happens on the update path when size limits are exceeded, so this
// interval only bounds how long reclaimable state lingers while the
// registry is otherwise idle.
const DomainRegistrySweepInterval = time.Minute

// A zero domain expiry means no expiry. Keeping that meaning in one set of
// helpers makes the heaps and capacity decisions treat it as positive
// infinity without manufacturing a distant timestamp.
func domainExpiryAlive(expiry, now time.Time) bool {
	return expiry.IsZero() || expiry.After(now)
}

func compareDomainExpiry(a, b time.Time) int {
	switch {
	case a.IsZero() && b.IsZero():
		return 0
	case a.IsZero():
		return 1
	case b.IsZero():
		return -1
	default:
		return a.Compare(b)
	}
}

// combineKernelIPExpiry derives one IP state's capacity priority. A no-expiry
// registration protects the complete IP state; otherwise its earliest
// registration expiry remains the priority as before.
func combineKernelIPExpiry(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	if a.Before(b) {
		return a
	}
	return b
}

// domainRegistration is one (domain, qtype) -> IP record learned from DNS.
// It is the single source of truth for both the kernel domain maps
// (domain_bump_map / domain_routing_map) and sniff verification. Its expiry
// (max(ttl, MinDomainTTL) after the last refresh, zero for no expiry) plays
// two roles:
//
//   - kernel contribution: while not expired and admitted (inKernel), the
//     record contributes to the per-IP bitmaps that are flushed into the
//     kernel maps. Expired kernel contributions are reaped proactively,
//     because a stale kernel bitmap actively costs performance (it bumps
//     traffic to the control plane).
//   - eviction priority: a present registration always proves "this domain
//     once resolved to this IP" for VerifySniff, even an expired one. Under
//     memory pressure gcUser reclaims the most stale records first; records
//     are never proactively removed just because expiry passed: that would
//     only save memory while breaking sniff verification (e.g. domain
//     fronting connections) for no other gain.
type domainRegistration struct {
	queryInfo
	ip            netip.Addr
	bitmap        []uint32 // match bitmap of the domain, length MaxMatchSetLen/32
	expiry        time.Time
	inKernel      bool
	kernelHeapIdx int
	verifyHeapIdx int
}

// ipKernelState is the set of in-kernel registrations of one IP. The
// bitmaps flushed to the kernel maps are recomputed from refs on every
// change:
//
//	domain_bump_map[ip]    bit i = OR of refs' bitmaps  // any cached domain matches
//	domain_routing_map[ip] bit i = AND of refs' bitmaps // all cached domains match
type ipKernelState struct {
	ip   netip.Addr
	refs map[*domainRegistration]struct{}
	// expiry is zero if any ref has no expiry; otherwise it is the earliest
	// expiry among refs. It is used only for capacity eviction priority.
	expiry  time.Time
	heapIdx int
}

// ipExpiryHeap orders complete in-kernel IP states by how long they remain
// useful. Kernel map capacity is counted in IPs, so capacity eviction must use
// the same unit instead of peeling individual registrations off a shared IP.
type ipExpiryHeap []*ipKernelState

func (h ipExpiryHeap) Len() int { return len(h) }
func (h ipExpiryHeap) Less(i, j int) bool {
	if c := compareDomainExpiry(h[i].expiry, h[j].expiry); c != 0 {
		return c < 0
	}
	return h[i].ip.Compare(h[j].ip) < 0
}
func (h ipExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx = i
	h[j].heapIdx = j
}
func (h *ipExpiryHeap) Push(x any) {
	s := x.(*ipKernelState)
	s.heapIdx = len(*h)
	*h = append(*h, s)
}
func (h *ipExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	s := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	s.heapIdx = -1
	return s
}

// expiryHeap is a min-heap of registrations ordered by expiry. setIdx keeps
// the registration's heap index up to date for O(log n) Fix/Remove.
type expiryHeap struct {
	items  []*domainRegistration
	setIdx func(*domainRegistration, int)
}

func (h expiryHeap) Len() int { return len(h.items) }
func (h expiryHeap) Less(i, j int) bool {
	return compareDomainExpiry(h.items[i].expiry, h.items[j].expiry) < 0
}
func (h expiryHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.setIdx(h.items[i], i)
	h.setIdx(h.items[j], j)
}
func (h *expiryHeap) Push(x any) {
	r := x.(*domainRegistration)
	h.setIdx(r, len(h.items))
	h.items = append(h.items, r)
}
func (h *expiryHeap) Pop() any {
	old := h.items
	n := len(old)
	r := old[n-1]
	old[n-1] = nil
	h.items = old[:n-1]
	h.setIdx(r, -1)
	return r
}

// DomainRegistry tracks every (domain, qtype) -> IP registration and keeps
// the kernel domain maps in sync with it.
//
// Capacity model:
//   - Kernel side is a hard limit (kernelMax, read from the eBPF map's
//     max_entries): admitting a new IP when full compares the complete
//     incoming IP state with complete resident IP states, keeping the states
//     with the latest expiry. An evicted IP's registrations survive in
//     userspace. Expired kernel contributions are also reaped periodically by
//     Sweep.
//   - Userspace side is a soft limit (userMax): once exceeded, memory-
//     pressure GC reclaims registrations with the earliest expiry, but only
//     expired ones; live registrations are never evicted, so the registry
//     may grow past userMax under churn. GC runs on the update path and on
//     the periodic sweep; expiry alone never removes a userspace
//     registration, because keeping it costs only memory while losing it
//     breaks sniff verification.
//
// Invariants (checked by tests):
//   - byIP contains exactly the IPs with >= 1 in-kernel registration, and
//     len(byIP) <= kernelMax.
//   - Every in-kernel registration is present in byName: the userspace
//     registry is a superset of the kernel state.
//   - len(kernelHeap) == number of in-kernel registrations; both heaps'
//     indices are consistent.
type DomainRegistry struct {
	mu sync.Mutex

	byName map[queryInfo]map[netip.Addr]*domainRegistration
	byAddr map[netip.Addr]map[*domainRegistration]struct{} // all userspace registrations
	byIP   map[netip.Addr]*ipKernelState                   // in-kernel IP states

	kernelHeap   expiryHeap   // in-kernel registrations, by expiry
	kernelIPHeap ipExpiryHeap // in-kernel IP states, by earliest expiry
	verifyHeap   expiryHeap   // all registrations, by expiry
	size         int          // total registrations

	kernelMax int
	userMax   int
	minTTL    time.Duration

	// update/remove push one IP's derived bitmaps into / out of the kernel
	// domain maps. They are fields so tests can run without eBPF. Failures
	// panic: kernel-map writes fail only on logic bugs or unrecoverable
	// kernel state, never on transient errors worth surviving.
	update func(ip netip.Addr, bump, routing []uint32)
	remove func(ip netip.Addr)

	closed  bool // set by Close: all mutating operations become no-ops
	adopted bool // set by AdoptFrom: kernel maps were synced, not wiped

	stopCh  chan struct{}
	doneCh  chan struct{}
	started bool
}

func newDomainRegistry(kernelMax, userMax int, minTTL time.Duration) *DomainRegistry {
	return &DomainRegistry{
		byName: make(map[queryInfo]map[netip.Addr]*domainRegistration),
		byAddr: make(map[netip.Addr]map[*domainRegistration]struct{}),
		byIP:   make(map[netip.Addr]*ipKernelState),
		kernelHeap: expiryHeap{
			setIdx: func(r *domainRegistration, i int) { r.kernelHeapIdx = i },
		},
		verifyHeap: expiryHeap{
			setIdx: func(r *domainRegistration, i int) { r.verifyHeapIdx = i },
		},
		kernelMax: kernelMax,
		userMax:   userMax,
		minTTL:    minTTL,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

func domainBitmapWords() int { return consts.MaxMatchSetLen / 32 }

func cloneDomainBitmap(bitmap []uint32) []uint32 {
	c := make([]uint32, domainBitmapWords())
	copy(c, bitmap)
	return c
}

func domainBitmapAllZero(bitmap []uint32) bool {
	for _, v := range bitmap {
		if v != 0 {
			return false
		}
	}
	return true
}

// Upsert registers or refreshes a (domain, qtype) -> IP record learned from
// a DNS response. ttl is the effective TTL in seconds (fixed_ttl when one is
// configured, otherwise the upstream TTL); the registration's expiry — kernel
// lifetime and userspace eviction priority alike — is max(ttl, minTTL).
// Capacity limits are enforced on this path (see the type doc).
func (g *DomainRegistry) Upsert(qi queryInfo, ip netip.Addr, bitmap []uint32, ttl int, now time.Time) {
	expiry := now.Add(max(time.Duration(ttl)*time.Second, g.minTTL))
	g.upsertWithExpiry(qi, ip, bitmap, expiry, now)
}

// UpsertNoExpiry registers a record without a time-based deadline. The lease
// survives registry adoption and dominates later finite-TTL refreshes of the
// same record, so an ordinary lookup cannot accidentally shorten a synthetic
// upstream lease.
func (g *DomainRegistry) UpsertNoExpiry(qi queryInfo, ip netip.Addr, bitmap []uint32, now time.Time) {
	g.upsertWithExpiry(qi, ip, bitmap, time.Time{}, now)
}

func (g *DomainRegistry) upsertWithExpiry(qi queryInfo, ip netip.Addr, bitmap []uint32, expiry, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	if len(bitmap) != domainBitmapWords() {
		panic(fmt.Errorf("domain bitmap length %v not in sync with MaxMatchSetLen", len(bitmap)))
	}
	if r := g.byName[qi][ip]; r != nil {
		// Preserve an existing no-expiry lease when the same record is later
		// observed in an ordinary finite-TTL DNS response.
		if r.expiry.IsZero() {
			expiry = time.Time{}
		}
		r.expiry = expiry
		heap.Fix(&g.verifyHeap, r.verifyHeapIdx)
		if !slices.Equal(r.bitmap, bitmap) {
			// Rules changed under this registration: drop the old
			// contribution entirely and re-admit with the new bitmap.
			g.detachKernel(r)
			r.bitmap = cloneDomainBitmap(bitmap)
		}
		if r.inKernel {
			heap.Fix(&g.kernelHeap, r.kernelHeapIdx)
			g.fixKernelIPExpiry(g.byIP[r.ip])
		}
		if !r.inKernel {
			g.attachKernel(r, now)
		}
		g.gcUser(now)
		return
	}

	r := &domainRegistration{
		queryInfo:     qi,
		ip:            ip,
		bitmap:        cloneDomainBitmap(bitmap),
		expiry:        expiry,
		kernelHeapIdx: -1,
		verifyHeapIdx: -1,
	}
	g.addRegistration(r)
	g.attachKernel(r, now)
	g.gcUser(now)
}

// Lookup returns the IPs the given (domain, qtype) is registered with. A
// present registration always proves the domain/IP pairing was learned from
// DNS — registrations are only removed by memory-pressure GC (gcUser), so
// this never expires on its own and can be trusted for sniff verification.
// An empty result means "no record" and the caller should fall back to
// other verification.
func (g *DomainRegistry) Lookup(qi queryInfo) []netip.Addr {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := g.byName[qi]
	if len(m) == 0 {
		return nil
	}
	ips := make([]netip.Addr, 0, len(m))
	for ip := range m {
		ips = append(ips, ip)
	}
	return ips
}

// DomainVerification separates historical DNS evidence from the current
// kernel routing state. A registration may remain Paired for sniff
// verification after its kernel contribution expires or is capacity-evicted;
// KernelCovered is false in those cases so while_needed routing can rerun the
// rule matcher in userspace.
type DomainVerification struct {
	Registered    bool
	Paired        bool
	KernelCovered bool
}

// Verify reports the historical verification state of (domain, qtype) and
// whether the current kernel domain maps cover the requested domain/IP pair.
// It is the O(1), allocation-free form of Lookup for sniff verification.
//
// An all-zero domain bitmap needs no kernel entry when the IP has no other
// domain-routing state: both kernel and userspace will miss every domain rule.
// If another domain does have state for the same IP, however, the zero-bitmap
// registration is not covered; the shared IP is ambiguous and userspace must
// rerun routing for the sniffed domain.
func (g *DomainRegistry) Verify(qi queryInfo, ip netip.Addr) (result DomainVerification) {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := g.byName[qi]
	if len(m) == 0 {
		return result
	}
	result.Registered = true
	r := m[ip]
	if r == nil {
		return result
	}
	result.Paired = true
	result.KernelCovered = r.inKernel || (domainBitmapAllZero(r.bitmap) && g.byIP[ip] == nil)
	return result
}

// Sweep reaps expired kernel contributions (registrations survive in
// userspace) and runs the userspace memory-pressure GC, so an idle registry
// over its soft limit does not hold stale records until the next insert.
func (g *DomainRegistry) Sweep(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	for g.kernelHeap.Len() > 0 {
		top := g.kernelHeap.items[0]
		if domainExpiryAlive(top.expiry, now) {
			break
		}
		heap.Pop(&g.kernelHeap)
		g.removeKernelContribution(top)
	}
	g.gcUser(now)
}

// AdoptFrom transfers all registrations from a retired plane's registry,
// recomputing every domain's match bitmap with this plane's routing rules
// (matchBitmap), and syncs the shared kernel maps to the adopted state:
// IPs that keep a non-empty bitmap are flushed, IPs that lost all rule
// matches under the new rules (or exceed the kernel capacity) are deleted
// from the maps. The kernel maps must NOT be wiped when this is used.
//
// Expirations are carried over unchanged: adoption does not extend the
// lifetime of any record. Adoption ends with the memory-pressure GC, so
// already-stale registrations over the userspace soft limit are reclaimed
// immediately rather than lingering until the first insert.
//
// It panics if this registry is not empty or the old one is still live:
// adoption rebuilds every registration from scratch, and inserting into a
// non-empty registry would silently corrupt the heap/index bookkeeping (a
// duplicated (domain, ip) overwrites the byName entry while the stale
// registration keeps living in the heaps and per-IP refs); a still-live old
// registry could keep writing the shared kernel maps and fight the adopted
// state. Both only happen on logic bugs.
func (g *DomainRegistry) AdoptFrom(old *DomainRegistry, matchBitmap func(fqdn string) []uint32, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	old.mu.Lock()
	defer old.mu.Unlock()
	if g.closed {
		return
	}
	if g.size != 0 || len(g.byName) != 0 || len(g.byAddr) != 0 || g.kernelHeap.Len() != 0 || len(g.kernelIPHeap) != 0 || g.verifyHeap.Len() != 0 {
		panic(fmt.Errorf("domain registry adopted into a non-empty registry (size=%v)", g.size))
	}
	if !old.closed {
		panic(fmt.Errorf("domain registry adopted from a registry that is still live"))
	}

	// Rebuild the registrations with this plane's rules and aggregate the
	// desired kernel state per IP.
	desired := make(map[netip.Addr]*ipKernelState)
	for qi, m := range old.byName {
		for ip, or := range m {
			nr := &domainRegistration{
				queryInfo:     qi,
				ip:            ip,
				bitmap:        cloneDomainBitmap(matchBitmap(qi.qname)),
				expiry:        or.expiry,
				kernelHeapIdx: -1,
				verifyHeapIdx: -1,
			}
			g.addRegistration(nr)
			if domainBitmapAllZero(nr.bitmap) || !domainExpiryAlive(or.expiry, now) {
				continue
			}
			s := desired[ip]
			if s == nil {
				s = &ipKernelState{
					ip:      ip,
					refs:    make(map[*domainRegistration]struct{}),
					expiry:  nr.expiry,
					heapIdx: -1,
				}
				desired[ip] = s
			} else {
				s.expiry = combineKernelIPExpiry(s.expiry, nr.expiry)
			}
			s.refs[nr] = struct{}{}
		}
	}

	// Enforce the kernel hard limit: drop the complete IP states whose first
	// registration expires earliest, keeping their registrations in userspace.
	if len(desired) > g.kernelMax {
		ips := make([]netip.Addr, 0, len(desired))
		for ip := range desired {
			ips = append(ips, ip)
		}
		slices.SortFunc(ips, func(a, b netip.Addr) int {
			if c := compareDomainExpiry(desired[a].expiry, desired[b].expiry); c != 0 {
				return c
			}
			return a.Compare(b)
		})
		for _, ip := range ips[:len(desired)-g.kernelMax] {
			delete(desired, ip)
		}
	}

	// Delete obsolete entries before inserting newly admitted IPs. The shared
	// kernel maps are non-LRU hash maps, so inserting first can fail at
	// max_entries even when the final desired state fits within kernelMax.
	for ip := range old.byIP {
		if _, ok := desired[ip]; !ok {
			g.remove(ip)
		}
	}

	// Flush adopted kernel state.
	for ip, s := range desired {
		g.byIP[ip] = s
		heap.Push(&g.kernelIPHeap, s)
		for nr := range s.refs {
			nr.inKernel = true
			heap.Push(&g.kernelHeap, nr)
		}
		g.flushIP(ip, s)
	}
	g.gcUser(now)
	g.adopted = true
}

// Adopted reports whether AdoptFrom has run: the kernel domain maps are in
// sync with this registry and must not be wiped on Activate.
func (g *DomainRegistry) Adopted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.adopted
}

// Size returns the total number of userspace registrations.
func (g *DomainRegistry) Size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.size
}

// KernelSize returns the number of IPs currently present in the kernel maps.
func (g *DomainRegistry) KernelSize() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.byIP)
}

// RegistryUsage is the fill of the userspace registry and the kernel maps
// against their respective limits.
type RegistryUsage struct {
	UserUsed   int
	UserMax    int
	KernelUsed int
	KernelMax  int
}

// Usage reports the current fill of both sides in one lock acquisition.
func (g *DomainRegistry) Usage() RegistryUsage {
	g.mu.Lock()
	defer g.mu.Unlock()
	return RegistryUsage{
		UserUsed:   g.size,
		UserMax:    g.userMax,
		KernelUsed: len(g.byIP),
		KernelMax:  g.kernelMax,
	}
}

// StartSweeper launches the periodic GC goroutine. Called once by the
// control plane core after the flush functions are bound.
func (g *DomainRegistry) StartSweeper() {
	g.mu.Lock()
	if g.started || g.closed {
		g.mu.Unlock()
		return
	}
	g.started = true
	g.mu.Unlock()
	go func() {
		defer close(g.doneCh)
		ticker := time.NewTicker(DomainRegistrySweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-g.stopCh:
				return
			case now := <-ticker.C:
				g.Sweep(now)
			}
		}
	}()
}

// Close synchronously stops the sweeper and disables all further mutations.
// Registrations are kept so a successor plane can still AdoptFrom a retired
// registry after its Close.
func (g *DomainRegistry) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	started := g.started
	g.mu.Unlock()
	if started {
		close(g.stopCh)
		<-g.doneCh
	}
	return nil
}

// addRegistration inserts a new registration into the userspace indexes.
// Callers handle kernel admission separately.
func (g *DomainRegistry) addRegistration(r *domainRegistration) {
	m := g.byName[r.queryInfo]
	if m == nil {
		m = make(map[netip.Addr]*domainRegistration)
		g.byName[r.queryInfo] = m
	}
	m[r.ip] = r
	refs := g.byAddr[r.ip]
	if refs == nil {
		refs = make(map[*domainRegistration]struct{})
		g.byAddr[r.ip] = refs
	}
	refs[r] = struct{}{}
	g.size++
	heap.Push(&g.verifyHeap, r)
}

// attachKernel admits a registration into the kernel accounting. If its IP
// was previously capacity-evicted, all of that IP's unexpired registrations
// are considered together so the kernel never sees an arbitrary subset of a
// shared IP. No-op for all-zero or already-expired registrations.
func (g *DomainRegistry) attachKernel(r *domainRegistration, now time.Time) {
	if r.inKernel || domainBitmapAllZero(r.bitmap) || !domainExpiryAlive(r.expiry, now) {
		return
	}
	s, ok := g.byIP[r.ip]
	if ok {
		s.refs[r] = struct{}{}
		r.inKernel = true
		heap.Push(&g.kernelHeap, r)
		g.fixKernelIPExpiry(s)
		g.flushIP(r.ip, s)
		return
	}

	// Build the complete incoming IP state, including live registrations
	// that survived an earlier capacity eviction in userspace.
	s = &ipKernelState{
		ip:      r.ip,
		refs:    make(map[*domainRegistration]struct{}),
		heapIdx: -1,
	}
	first := true
	for candidate := range g.byAddr[r.ip] {
		if domainBitmapAllZero(candidate.bitmap) || !domainExpiryAlive(candidate.expiry, now) {
			continue
		}
		s.refs[candidate] = struct{}{}
		if first {
			s.expiry = candidate.expiry
			first = false
		} else {
			s.expiry = combineKernelIPExpiry(s.expiry, candidate.expiry)
		}
	}
	if len(s.refs) == 0 || g.kernelMax <= 0 {
		return
	}

	if len(g.byIP) >= g.kernelMax {
		if len(g.kernelIPHeap) == 0 {
			return
		}
		victim := g.kernelIPHeap[0]
		// Include the incoming state in the ranking. On a tie, retain the
		// resident to avoid needless map churn.
		if compareDomainExpiry(s.expiry, victim.expiry) <= 0 {
			return
		}
		g.evictKernelIP(victim)
	}

	g.byIP[r.ip] = s
	heap.Push(&g.kernelIPHeap, s)
	for candidate := range s.refs {
		candidate.inKernel = true
		heap.Push(&g.kernelHeap, candidate)
	}
	g.flushIP(r.ip, s)
}

// detachKernel withdraws a registration's kernel contribution.
func (g *DomainRegistry) detachKernel(r *domainRegistration) {
	if !r.inKernel {
		return
	}
	heap.Remove(&g.kernelHeap, r.kernelHeapIdx)
	g.removeKernelContribution(r)
}

// removeKernelContribution undoes attachKernel's accounting. The caller must
// have removed r from kernelHeap already.
func (g *DomainRegistry) removeKernelContribution(r *domainRegistration) {
	r.inKernel = false
	s := g.byIP[r.ip]
	if s == nil {
		return
	}
	delete(s.refs, r)
	if len(s.refs) == 0 {
		heap.Remove(&g.kernelIPHeap, s.heapIdx)
		delete(g.byIP, r.ip)
		g.remove(r.ip)
		return
	}
	g.fixKernelIPExpiry(s)
	g.flushIP(r.ip, s)
}

// evictKernelIP withdraws a complete IP state without flushing any partial
// intermediate bitmap. Its registrations remain available in userspace and
// can be reconsidered together on a later refresh.
func (g *DomainRegistry) evictKernelIP(s *ipKernelState) {
	heap.Remove(&g.kernelIPHeap, s.heapIdx)
	for r := range s.refs {
		heap.Remove(&g.kernelHeap, r.kernelHeapIdx)
		r.inKernel = false
	}
	delete(g.byIP, s.ip)
	g.remove(s.ip)
}

// fixKernelIPExpiry recomputes a resident IP state's capacity-eviction
// priority. A no-expiry ref protects the complete IP state; otherwise its
// earliest registration expiry represents the state.
func (g *DomainRegistry) fixKernelIPExpiry(s *ipKernelState) {
	if s == nil || len(s.refs) == 0 {
		return
	}
	var expiry time.Time
	first := true
	for r := range s.refs {
		if first {
			expiry = r.expiry
			first = false
		} else {
			expiry = combineKernelIPExpiry(expiry, r.expiry)
		}
	}
	s.expiry = expiry
	heap.Fix(&g.kernelIPHeap, s.heapIdx)
}

// unregister fully removes a registration (userspace and kernel).
func (g *DomainRegistry) unregister(r *domainRegistration) {
	if r.inKernel {
		g.detachKernel(r)
	}
	heap.Remove(&g.verifyHeap, r.verifyHeapIdx)
	m := g.byName[r.queryInfo]
	delete(m, r.ip)
	if len(m) == 0 {
		delete(g.byName, r.queryInfo)
	}
	refs := g.byAddr[r.ip]
	delete(refs, r)
	if len(refs) == 0 {
		delete(g.byAddr, r.ip)
	}
	g.size--
}

// gcUser enforces the userspace soft limit: while over userMax, reclaim the
// registrations with the earliest expiry, but only expired ones —
// live records are never evicted and the registry may exceed userMax.
func (g *DomainRegistry) gcUser(now time.Time) {
	for g.size > g.userMax && g.verifyHeap.Len() > 0 {
		top := g.verifyHeap.items[0]
		if domainExpiryAlive(top.expiry, now) {
			return
		}
		g.unregister(top)
	}
}

// flushIP derives the bump/routing bitmaps from the registrations in s and
// pushes them to the kernel maps via the bound update function: bump is the
// OR of all bitmaps (any domain matches), routing the AND (all domains
// match). Callers must ensure s.refs is non-empty.
func (g *DomainRegistry) flushIP(ip netip.Addr, s *ipKernelState) {
	bump := make([]uint32, domainBitmapWords())
	routing := make([]uint32, domainBitmapWords())
	first := true
	for r := range s.refs {
		for w, bits := range r.bitmap {
			bump[w] |= bits
			if first {
				routing[w] = bits
			} else {
				routing[w] &= bits
			}
		}
		first = false
	}
	g.update(ip, bump, routing)
}
