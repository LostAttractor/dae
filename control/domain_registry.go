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
// It is the single source of truth for both the kernel domain map and sniff
// verification. Its effective expiry (the longest observed
// max(ttl, MinDomainTTL) lease, or zero while this plane has a no-expiry
// observation) plays two roles:
//
//   - kernel contribution: while not expired and admitted (inKernel), the
//     record contributes to the per-IP bitmaps that are flushed into the
//     kernel map. Expired kernel contributions are reaped proactively,
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
	ip netip.Addr
	// Registrations of the same query share this immutable bitmap in the
	// common case. A changed bitmap is cloned for only the updated record.
	bitmap        []uint32  // match bitmap of the domain, length MaxMatchSetLen/32
	finiteExpiry  time.Time // longest finite observation; retained under no-expiry
	noExpiry      bool      // plane-local no-expiry observation
	inKernel      bool
	userLive      bool
	kernelHeapIdx int
	verifyHeapIdx int
}

func (r *domainRegistration) effectiveExpiry() time.Time {
	if r.noExpiry {
		return time.Time{}
	}
	return r.finiteExpiry
}

// ipKernelState is the set of in-kernel registrations of one IP. Its cached
// bitmaps are updated incrementally when refs are added and recomputed when a
// ref is changed or removed:
//
//	domain_routing_map[ip].bump[i]    = OR of refs' bitmaps  // any domain matches
//	domain_routing_map[ip].routing[i] = AND of refs' bitmaps // all domains match
//
// A resident state contains every live registration for the IP, including
// all-zero bitmaps. The state exists only while its aggregate bump is nonzero.
type ipKernelState struct {
	ip      netip.Addr
	refs    map[*domainRegistration]struct{}
	bump    []uint32
	routing []uint32
	dirty   bool
	// expiry is zero if any ref has no expiry; otherwise it is the earliest
	// expiry among refs. It is used only for capacity eviction priority.
	expiry  time.Time
	heapIdx int
}

type nonzeroIPState struct {
	count    int
	noExpiry int
	latest   time.Time
	dirty    bool
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
	return compareDomainExpiry(h.items[i].effectiveExpiry(), h.items[j].effectiveExpiry()) < 0
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
// the kernel domain map in sync with it.
//
// Capacity model:
//   - Kernel side is a hard limit (kernelMax, read from the eBPF map's
//     max_entries): admitting a new IP when full compares the complete
//     incoming IP state with complete resident IP states, keeping the states
//     with the latest expiry. An evicted IP's registrations survive in
//     userspace. Expired kernel contributions are also reaped periodically by
//     Sweep.
//   - Userspace side is a hard limit (userMax): once exceeded, GC reclaims
//     registrations with the earliest expiry, including live registrations
//     when necessary. GC runs on the update path and on the periodic sweep;
//     expiry alone never removes a userspace registration below the limit,
//     because retained history remains useful for sniff verification.
//
// Invariants (checked by tests):
//   - byIP contains exactly the IPs with >= 1 in-kernel registration, and
//     len(byIP) <= kernelMax.
//   - A byIP state contains every live registration for its IP, including
//     all-zero bitmaps, and its aggregate bump is nonzero.
//   - Every in-kernel registration is present in byName: the userspace
//     registry is a superset of the kernel state.
//   - len(kernelHeap) == number of in-kernel registrations; both heaps'
//     indices are consistent.
//   - len(verifyHeap) <= userMax.
//   - userLive is the number of registrations classified as live by their
//     latest update or the latest periodic sweep.
type DomainRegistry struct {
	mu sync.Mutex

	byName map[queryInfo]map[netip.Addr]*domainRegistration
	byAddr map[netip.Addr]map[*domainRegistration]struct{} // all userspace registrations
	byIP   map[netip.Addr]*ipKernelState                   // in-kernel IP states
	// nonzeroByIP lets all-zero inserts skip candidate reconstruction while
	// still allowing them to reconsider an IP with existing nonzero evidence.
	nonzeroByIP map[netip.Addr]*nonzeroIPState

	kernelHeap   expiryHeap   // in-kernel registrations, by expiry
	kernelIPHeap ipExpiryHeap // in-kernel IP states, by earliest expiry
	verifyHeap   expiryHeap   // all registrations, by expiry
	evaluatedAt  time.Time    // latest observation/sweep time used for liveness
	userLive     int          // sweep-cached live userspace registrations
	limitGC      uint64       // registrations reclaimed to enforce userMax

	kernelMax int
	userMax   int
	minTTL    time.Duration

	// update/remove push one IP's derived bitmaps into / out of the kernel
	// domain map. They are fields so tests can run without eBPF. Failures
	// panic: kernel-map writes fail only on logic bugs or unrecoverable
	// kernel state, never on transient errors worth surviving.
	update func(ip netip.Addr, bump, routing []uint32)
	remove func(ip netip.Addr)

	closed  bool // set by Close: all mutating operations become no-ops
	adopted bool // set by AdoptFrom: kernel map was synced, not wiped

	stopCh  chan struct{}
	doneCh  chan struct{}
	started bool
}

func newDomainRegistry(kernelMax, userMax int, minTTL time.Duration) *DomainRegistry {
	return &DomainRegistry{
		byName:      make(map[queryInfo]map[netip.Addr]*domainRegistration),
		byAddr:      make(map[netip.Addr]map[*domainRegistration]struct{}),
		byIP:        make(map[netip.Addr]*ipKernelState),
		nonzeroByIP: make(map[netip.Addr]*nonzeroIPState),
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

// shareDomainBitmap reuses an equal bitmap already owned by the same query.
// Domain matching depends on qname, so all addresses observed for one query
// normally have identical bitmaps. Keeping the slice on registrations avoids
// another indexing layer while removing the dominant duplicate allocation.
func (g *DomainRegistry) shareDomainBitmap(qi queryInfo, bitmap []uint32, except *domainRegistration) []uint32 {
	for _, r := range g.byName[qi] {
		if r != except && slices.Equal(r.bitmap, bitmap) {
			return r.bitmap
		}
	}
	return cloneDomainBitmap(bitmap)
}

func domainBitmapAllZero(bitmap []uint32) bool {
	for _, v := range bitmap {
		if v != 0 {
			return false
		}
	}
	return true
}

// UpsertObserved records an ordinary DNS lease from observedAt while using
// evaluatedAt to decide whether delayed publication is still live.
func (g *DomainRegistry) UpsertObserved(qi queryInfo, ip netip.Addr, bitmap []uint32, ttl int, observedAt, evaluatedAt time.Time) {
	expiry := observedAt.Add(max(time.Duration(ttl)*time.Second, g.minTTL))
	g.upsertWithExpiry(qi, ip, bitmap, expiry, false, false, evaluatedAt)
}

// UpsertWithDeadline records evidence whose lifetime must not be extended by
// minTTL, such as an RRset bounded by an RRSIG expiration. Expired evidence is
// not trusted or retained.
func (g *DomainRegistry) UpsertWithDeadline(qi queryInfo, ip netip.Addr, bitmap []uint32, deadline, now time.Time) {
	g.upsertWithExpiry(qi, ip, bitmap, deadline, false, true, now)
}

// UpsertNoExpiry registers a record without a time-based deadline. The lease
// dominates later finite-TTL refreshes of the same record, so an ordinary
// lookup cannot accidentally shorten a synthetic upstream lease. The
// no-expiry observation is plane-local and is dropped by AdoptFrom, while any
// finite observation for the same tuple is retained.
func (g *DomainRegistry) UpsertNoExpiry(qi queryInfo, ip netip.Addr, bitmap []uint32, now time.Time) {
	g.upsertWithExpiry(qi, ip, bitmap, time.Time{}, true, false, now)
}

func (g *DomainRegistry) upsertWithExpiry(qi queryInfo, ip netip.Addr, bitmap []uint32, expiry time.Time, noExpiry, requireLive bool, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	if len(bitmap) != domainBitmapWords() {
		panic(fmt.Errorf("domain bitmap length %v not in sync with MaxMatchSetLen", len(bitmap)))
	}
	if requireLive {
		if current := time.Now(); current.After(now) {
			now = current
		}
	}
	if now.After(g.evaluatedAt) {
		g.evaluatedAt = now
	} else {
		now = g.evaluatedAt
	}
	if requireLive && !expiry.After(now) {
		return
	}
	if r := g.byName[qi][ip]; r != nil {
		oldNonzero := !domainBitmapAllZero(r.bitmap)
		oldExpiry := r.effectiveExpiry()
		// Registrations aggregate observations from caches with different
		// upstream/dialer keys. A plane-local no-expiry observation dominates
		// the effective lifetime, but it must not erase finite evidence that a
		// successor plane can adopt.
		if noExpiry {
			r.noExpiry = true
		} else if r.finiteExpiry.Before(expiry) {
			r.finiteExpiry = expiry
		}
		heap.Fix(&g.verifyHeap, r.verifyHeapIdx)
		g.refreshUserLiveness(r, now)
		bitmapChanged := !slices.Equal(r.bitmap, bitmap)
		if bitmapChanged {
			r.bitmap = g.shareDomainBitmap(qi, bitmap, r)
		}
		g.replaceNonzeroContribution(ip, oldNonzero, oldExpiry, !domainBitmapAllZero(r.bitmap), r.effectiveExpiry())
		if r.inKernel {
			heap.Fix(&g.kernelHeap, r.kernelHeapIdx)
			s := g.byIP[r.ip]
			if bitmapChanged {
				g.rebuildKernelIPState(s)
				g.reconcileIP(s)
			} else {
				g.fixKernelIPExpiry(s)
			}
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
		bitmap:        g.shareDomainBitmap(qi, bitmap, nil),
		finiteExpiry:  expiry,
		noExpiry:      noExpiry,
		kernelHeapIdx: -1,
		verifyHeapIdx: -1,
	}
	g.addRegistration(r, now)
	g.attachKernel(r, now)
	g.gcUser(now)
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
// whether the current kernel domain map covers the requested domain/IP pair.
// It is the O(1), allocation-free form of lookup for sniff verification.
//
// An all-zero domain bitmap needs no kernel entry when the IP has no other
// domain-routing state: both kernel and userspace will miss every domain rule.
// When another live domain creates state for the IP, the zero-bitmap
// registration joins that state and clears routing AND bits as needed.
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
// userspace below the limit) and enforces the userspace history limit.
func (g *DomainRegistry) Sweep(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	if now.After(g.evaluatedAt) {
		g.evaluatedAt = now
	} else {
		now = g.evaluatedAt
	}
	g.refreshAllUserLiveness(now)
	g.gcUser(now)
}

// reapExpiredKernel removes every expired resident ref first, then reconciles
// each affected IP once. This keeps both Sweep and memory-pressure GC linear
// for a shared IP with many records expiring together.
func (g *DomainRegistry) reapExpiredKernel(now time.Time) {
	var affected map[netip.Addr]*ipKernelState
	for g.kernelHeap.Len() > 0 {
		top := g.kernelHeap.items[0]
		if domainExpiryAlive(top.effectiveExpiry(), now) {
			break
		}
		heap.Pop(&g.kernelHeap)
		top.inKernel = false
		if s := g.byIP[top.ip]; s != nil {
			delete(s.refs, top)
			if affected == nil {
				affected = make(map[netip.Addr]*ipKernelState)
			}
			affected[top.ip] = s
		}
	}
	for _, s := range affected {
		g.rebuildKernelIPState(s)
		g.reconcileIP(s)
	}
}

// AdoptFrom transfers finite observations from a retired plane's registry,
// recomputing every domain's match bitmap with this plane's routing rules
// (matchBitmap), and syncs the shared kernel map to the adopted state.
// Plane-local no-expiry observations are dropped; when a registration has
// both kinds of provenance, its finite observation is still adopted. Pure
// no-expiry registrations are omitted and rebuilt by the new resolver.
// IPs whose aggregate bump becomes zero (or exceed kernel capacity) are
// deleted from the map. The kernel map must NOT be wiped when this is used.
//
// Expirations are carried over unchanged: adoption does not extend the
// lifetime of any record. Adoption ends with the memory-pressure GC, so
// already-stale registrations over the userspace limit are reclaimed
// immediately rather than lingering until the first insert.
//
// It panics if this registry is not empty or the old one is still live:
// adoption rebuilds every registration from scratch, and inserting into a
// non-empty registry would silently corrupt the heap/index bookkeeping (a
// duplicated (domain, ip) overwrites the byName entry while the stale
// registration keeps living in the heaps and per-IP refs); a still-live old
// registry could keep writing the shared kernel map and fight the adopted
// state. Both only happen on logic bugs.
func (g *DomainRegistry) AdoptFrom(old *DomainRegistry, matchBitmap func(fqdn string) []uint32, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	old.mu.Lock()
	defer old.mu.Unlock()
	if g.closed {
		return
	}
	if g.verifyHeap.Len() != 0 || g.userLive != 0 || len(g.byName) != 0 || len(g.byAddr) != 0 || len(g.nonzeroByIP) != 0 || g.kernelHeap.Len() != 0 || len(g.kernelIPHeap) != 0 {
		panic(fmt.Errorf("domain registry adopted into a non-empty registry (size=%v)", g.verifyHeap.Len()))
	}
	if !old.closed {
		panic(fmt.Errorf("domain registry adopted from a registry that is still live"))
	}
	if g.evaluatedAt.After(now) {
		now = g.evaluatedAt
	}
	if old.evaluatedAt.After(now) {
		now = old.evaluatedAt
	}
	g.evaluatedAt = now
	g.limitGC = old.limitGC

	// Rebuild finite observations with this plane's rules. Historical expired
	// observations remain userspace evidence, as they did before adoption.
	for qi, m := range old.byName {
		bitmap := matchBitmap(qi.qname)
		if len(bitmap) != domainBitmapWords() {
			panic(fmt.Errorf("domain bitmap length %v not in sync with MaxMatchSetLen", len(bitmap)))
		}
		sharedBitmap := cloneDomainBitmap(bitmap)
		for ip, or := range m {
			if or.finiteExpiry.IsZero() {
				continue
			}
			nr := &domainRegistration{
				queryInfo:     qi,
				ip:            ip,
				bitmap:        sharedBitmap,
				finiteExpiry:  or.finiteExpiry,
				kernelHeapIdx: -1,
				verifyHeapIdx: -1,
			}
			g.addRegistration(nr, now)
		}
	}

	// Aggregate complete live IP states only after every registration has
	// been rebuilt, so zero-bit registrations participate in routing AND.
	desired := make(map[netip.Addr]*ipKernelState)
	for ip := range g.byAddr {
		if s := g.buildKernelIPState(ip, now); s != nil {
			desired[ip] = s
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
	// kernel map is a non-LRU hash map, so inserting first can fail at
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
		g.reconcileIP(s)
	}
	g.gcUser(now)
	g.adopted = true
}

// Adopted reports whether AdoptFrom has run: the kernel domain map is in
// sync with this registry and must not be wiped on Activate.
func (g *DomainRegistry) Adopted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.adopted
}

// RegistryUsage is the fill of the userspace registry and the kernel map
// against their respective limits.
type RegistryUsage struct {
	UserUsed     int
	UserLive     int
	UserRetained int
	UserMax      int
	LimitGC      uint64
	KernelUsed   int
	KernelMax    int
}

// Usage reports the current fill of both sides in one lock acquisition. Live
// and retained counts are cached by updates and the periodic sweep, so this
// stays O(1) even when the userspace registry is at capacity. With the sweeper
// running, time-driven transitions for untouched records lag wall time by at
// most one sweep interval.
func (g *DomainRegistry) Usage() RegistryUsage {
	g.mu.Lock()
	defer g.mu.Unlock()
	userUsed := g.verifyHeap.Len()
	userLive := g.userLive
	return RegistryUsage{
		UserUsed:     userUsed,
		UserLive:     userLive,
		UserRetained: userUsed - userLive,
		UserMax:      g.userMax,
		LimitGC:      g.limitGC,
		KernelUsed:   len(g.byIP),
		KernelMax:    g.kernelMax,
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
		ticker := time.NewTicker(consts.DnsStateSweepInterval)
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
	now := time.Now()
	if g.evaluatedAt.After(now) {
		now = g.evaluatedAt
	}
	g.refreshAllUserLiveness(now)
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
func (g *DomainRegistry) addRegistration(r *domainRegistration, now time.Time) {
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
	g.replaceNonzeroContribution(r.ip, false, time.Time{}, !domainBitmapAllZero(r.bitmap), r.effectiveExpiry())
	heap.Push(&g.verifyHeap, r)
	if domainExpiryAlive(r.effectiveExpiry(), now) {
		r.userLive = true
		g.userLive++
	}
}

// refreshUserLiveness updates the status classification for one registration.
// Untouched time-driven transitions are handled together by the periodic
// sweep, keeping Usage itself constant-time.
func (g *DomainRegistry) refreshUserLiveness(r *domainRegistration, now time.Time) {
	live := domainExpiryAlive(r.effectiveExpiry(), now)
	if live == r.userLive {
		return
	}
	r.userLive = live
	if live {
		g.userLive++
	} else {
		g.userLive--
	}
}

func (g *DomainRegistry) refreshAllUserLiveness(now time.Time) {
	userLive := 0
	for _, r := range g.verifyHeap.items {
		r.userLive = domainExpiryAlive(r.effectiveExpiry(), now)
		if r.userLive {
			userLive++
		}
	}
	g.userLive = userLive
}

func (g *DomainRegistry) replaceNonzeroContribution(ip netip.Addr, oldNonzero bool, oldExpiry time.Time, newNonzero bool, newExpiry time.Time) {
	if oldNonzero == newNonzero && oldExpiry.Equal(newExpiry) {
		return
	}
	s := g.nonzeroByIP[ip]
	if oldNonzero {
		s.count--
		if oldExpiry.IsZero() {
			s.noExpiry--
		} else if oldExpiry.Equal(s.latest) {
			s.dirty = true
		}
	}
	if newNonzero {
		if s == nil {
			s = &nonzeroIPState{}
			g.nonzeroByIP[ip] = s
		}
		s.count++
		if newExpiry.IsZero() {
			s.noExpiry++
		} else if s.latest.IsZero() || !newExpiry.Before(s.latest) {
			s.latest = newExpiry
			s.dirty = false
		}
	}
	if s != nil && s.count == 0 {
		delete(g.nonzeroByIP, ip)
	}
}

func (g *DomainRegistry) rebuildNonzeroIPState(ip netip.Addr) *nonzeroIPState {
	s := new(nonzeroIPState)
	for r := range g.byAddr[ip] {
		if domainBitmapAllZero(r.bitmap) {
			continue
		}
		s.count++
		expiry := r.effectiveExpiry()
		if expiry.IsZero() {
			s.noExpiry++
		} else if s.latest.IsZero() || expiry.After(s.latest) {
			s.latest = expiry
		}
	}
	if s.count == 0 {
		delete(g.nonzeroByIP, ip)
		return nil
	}
	g.nonzeroByIP[ip] = s
	return s
}

func (g *DomainRegistry) hasLiveNonzero(ip netip.Addr, now time.Time) bool {
	s := g.nonzeroByIP[ip]
	if s == nil {
		return false
	}
	if s.noExpiry > 0 {
		return true
	}
	if !s.latest.After(now) {
		return false
	}
	if s.dirty {
		s = g.rebuildNonzeroIPState(ip)
	}
	return s != nil && (s.noExpiry > 0 || s.latest.After(now))
}

// attachKernel admits a registration into the kernel accounting. If its IP
// was previously capacity-evicted, all of that IP's unexpired registrations
// are considered together so the kernel never sees an arbitrary subset of a
// shared IP. An all-zero registration joins an existing state, but cannot
// create a state unless another live registration makes the aggregate bump
// nonzero. Already-expired registrations are ignored.
func (g *DomainRegistry) attachKernel(r *domainRegistration, now time.Time) {
	expiry := r.effectiveExpiry()
	if r.inKernel || !domainExpiryAlive(expiry, now) {
		return
	}
	s, ok := g.byIP[r.ip]
	if ok {
		s.refs[r] = struct{}{}
		for w, bits := range r.bitmap {
			bump := s.bump[w] | bits
			routing := s.routing[w] & bits
			s.dirty = s.dirty || bump != s.bump[w] || routing != s.routing[w]
			s.bump[w] = bump
			s.routing[w] = routing
		}
		s.expiry = combineKernelIPExpiry(s.expiry, expiry)
		r.inKernel = true
		heap.Push(&g.kernelHeap, r)
		g.reconcileIP(s)
		return
	}
	if domainBitmapAllZero(r.bitmap) && !g.hasLiveNonzero(r.ip, now) {
		return
	}

	// Build the complete incoming IP state, including live registrations
	// that survived an earlier capacity eviction in userspace.
	s = g.buildKernelIPState(r.ip, now)
	if s == nil || g.kernelMax <= 0 {
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
	g.reconcileIP(s)
}

// buildKernelIPState collects every live registration for ip. It returns nil
// when the complete aggregate has no bump bits, because a kernel map miss is
// already the exact representation of that state.
func (g *DomainRegistry) buildKernelIPState(ip netip.Addr, now time.Time) *ipKernelState {
	s := &ipKernelState{
		ip:      ip,
		refs:    make(map[*domainRegistration]struct{}),
		heapIdx: -1,
	}
	for r := range g.byAddr[ip] {
		if domainExpiryAlive(r.effectiveExpiry(), now) {
			s.refs[r] = struct{}{}
		}
	}
	if len(s.refs) == 0 {
		return nil
	}
	s.bump, s.routing, s.expiry = aggregateKernelRefs(s.refs)
	if domainBitmapAllZero(s.bump) {
		return nil
	}
	s.dirty = true
	return s
}

// detachKernel withdraws a registration's kernel contribution.
func (g *DomainRegistry) detachKernel(r *domainRegistration) {
	if !r.inKernel {
		return
	}
	heap.Remove(&g.kernelHeap, r.kernelHeapIdx)
	r.inKernel = false
	s := g.byIP[r.ip]
	if s == nil {
		return
	}
	delete(s.refs, r)
	g.rebuildKernelIPState(s)
	g.reconcileIP(s)
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
	first := true
	var expiry time.Time
	for r := range s.refs {
		if first {
			expiry = r.effectiveExpiry()
			first = false
		} else {
			expiry = combineKernelIPExpiry(expiry, r.effectiveExpiry())
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
	if r.userLive {
		g.userLive--
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
	g.replaceNonzeroContribution(r.ip, !domainBitmapAllZero(r.bitmap), r.effectiveExpiry(), false, time.Time{})
}

// gcUser enforces the userspace history hard limit. Expired registrations
// naturally sort first; live history is reclaimed only when it is necessary
// to keep memory bounded.
func (g *DomainRegistry) gcUser(now time.Time) {
	g.reapExpiredKernel(now)
	for g.verifyHeap.Len() > g.userMax && g.verifyHeap.Len() > 0 {
		top := g.verifyHeap.items[0]
		g.unregister(top)
		g.limitGC++
	}
}

// aggregateKernelRefs derives a complete IP state in one pass: bump is the OR
// of every live registration's bitmap, routing is their AND, and expiry keeps
// the existing capacity priority (no-expiry wins, otherwise earliest first).
func aggregateKernelRefs(refs map[*domainRegistration]struct{}) (bump, routing []uint32, expiry time.Time) {
	bump = make([]uint32, domainBitmapWords())
	routing = make([]uint32, domainBitmapWords())
	first := true
	for r := range refs {
		for w, bits := range r.bitmap {
			bump[w] |= bits
			if first {
				routing[w] = bits
			} else {
				routing[w] &= bits
			}
		}
		if first {
			expiry = r.effectiveExpiry()
		} else {
			expiry = combineKernelIPExpiry(expiry, r.effectiveExpiry())
		}
		first = false
	}
	return bump, routing, expiry
}

// rebuildKernelIPState recomputes cached state after a ref changes or leaves.
// New refs use the incremental path in attachKernel.
func (g *DomainRegistry) rebuildKernelIPState(s *ipKernelState) {
	bump, routing, expiry := aggregateKernelRefs(s.refs)
	s.dirty = s.dirty || !slices.Equal(s.bump, bump) || !slices.Equal(s.routing, routing)
	s.bump = bump
	s.routing = routing
	s.expiry = expiry
}

// reconcileIP is the single path that publishes or withdraws a resident IP's
// cached kernel state. A zero bump is represented exactly by a map miss.
func (g *DomainRegistry) reconcileIP(s *ipKernelState) {
	if len(s.refs) == 0 || domainBitmapAllZero(s.bump) {
		g.evictKernelIP(s)
		return
	}
	heap.Fix(&g.kernelIPHeap, s.heapIdx)
	if s.dirty {
		g.update(s.ip, s.bump, s.routing)
		s.dirty = false
	}
}
