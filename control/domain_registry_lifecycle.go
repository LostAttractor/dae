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

// Start is called once by the owner before publishing the registry. One worker
// owns activity batches, GC, renewal windows and compaction; mutations append
// their new pairs themselves. Writing starts after activation.
func (g *DomainRegistry) Start() {
	// A rejected successor may resume its predecessor's joined worker.
	select {
	case <-g.stopCh:
		g.stopCh, g.stopOnce = make(chan struct{}), sync.Once{}
	default:
	}
	g.workerDone = make(chan struct{})
	go func() {
		defer close(g.workerDone)
		activity := time.NewTicker(time.Second)
		sweep := time.NewTicker(consts.DnsStateSweepInterval)
		defer activity.Stop()
		defer sweep.Stop()
		for {
			select {
			case <-g.stopCh:
				return
			case now := <-activity.C:
				g.flushActivity()
				g.retryProjection(now)
				// The window ends after the activity it covers is applied.
				if g.renewalDue(now) {
					g.writeRenewals(now)
				}
			case now := <-sweep.C:
				g.Sweep(now)
			case <-g.persistWake:
				g.writeNew(time.Now())
			}
		}
	}()
}

func (g *DomainRegistry) stopWorker() {
	g.stopOnce.Do(func() { close(g.stopCh) })
	if g.workerDone != nil {
		<-g.workerDone
	}
}

func (g *DomainRegistry) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		<-g.closeDone
		return nil
	}
	a := g.activity
	a.lock()
	g.closed = true
	if a.registry == g {
		a.pending, g.activityBatch = g.activityBatch, a.pending
		a.registry = nil
	}
	a.unlock()
	// Only the queue's current owner takes a final batch. Closing a predecessor
	// must not drain activity destined for its successor.
	reconsider := g.applyActivity()
	g.syncProjection(g.gc(g.evaluatedAt), reconsider, g.evaluatedAt)
	g.mu.Unlock()
	defer close(g.closeDone)
	g.stopWorker()
	// The worker has stopped, so Close is the writer. Disk durability is
	// best-effort: a failure is logged and never prevents retirement.
	g.writeRenewals(time.Now())
	g.closePersistence()
	return nil
}

// installRecords is shared by cold restore and reload. Caller holds mu on a
// fresh registry and owns the supplied records; attach current-rule bitmaps and
// index their shared pairs using the maps allocated by the constructor.
func (g *DomainRegistry) installRecords(records map[string]*domainRecord, matchBitmap func(string) []uint32) {
	g.due = slices.Grow(g.due[:0], len(records))
	for name, r := range records {
		r.name, r.bitmap = name, slices.Clone(matchBitmap(name))
		first := true
		for ip, pair := range r.addresses {
			g.indexPair(r, ip, pair)
			if first || pair.retainUntil.Before(r.expiry) {
				r.expiry, first = pair.retainUntil, false
			}
		}
		g.due = append(g.due, r)
		r.slot = len(g.due)
	}
	heap.Init(&g.due)
	g.byName = records
}

// ForkFrom publishes an independent projection without stopping old request
// handlers. Runtime serializes DNS delivery with this snapshot and fans later
// observations out to every serving generation using its own domain matcher.
func (g *DomainRegistry) ForkFrom(old *DomainRegistry, matchBitmap func(string) []uint32, now time.Time) (err error) {
	// Join the old writer before the successor takes over its files.
	old.stopWorker()
	defer func() {
		if err != nil && old.workerDone != nil {
			old.Start()
		}
	}()
	// Mutations still appending finish first. The candidate writes nothing
	// until it is admitted; pairs queued meanwhile wait for the owner's worker.
	old.mu.Lock()
	l := old.persist
	old.mu.Unlock()
	if l != nil {
		l.io.Lock()
		defer l.io.Unlock()
	}
	old.mu.Lock()
	defer old.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	reconsider := old.drainActivity()
	old.syncProjection(old.gc(old.evaluatedAt), reconsider, old.evaluatedAt)
	// The successor journals every change from here on, including handoff
	// activity applied below. Pairs keep their ordinals, and the open window
	// lists the copies of the pairs it listed.
	g.persist, old.persist = l, nil
	g.gcCount = old.gcCount
	var listed []*domainPair
	records := make(map[string]*domainRecord, len(old.byName))
	for name, r := range old.byName {
		addresses := make(map[netip.Addr]*domainPair, len(r.addresses))
		for ip, pair := range r.addresses {
			copied := &domainPair{retainUntil: pair.retainUntil, ordinal: pair.ordinal, listed: pair.listed}
			addresses[ip] = copied
			if l != nil && !l.rebuild && pair.listed == l.window {
				listed = append(listed, copied)
			}
		}
		records[name] = &domainRecord{addresses: addresses}
	}
	var previous []*domainPair
	if l != nil {
		previous, l.renewed = l.renewed, listed
	}
	g.installRecords(records, matchBitmap)
	g.clock(old.evaluatedAt)
	a := old.activity
	// Copy queued activity into the candidate without consuming it. On a map
	// failure the old owner must still be able to process the complete queue.
	a.lock()
	for i, pending := range a.pending {
		if g.activityBatch[i] == nil && len(pending) != 0 {
			g.activityBatch[i] = make(map[domainActivityKey]time.Time, len(pending))
		}
		maps.Copy(g.activityBatch[i], pending)
	}
	g.applyActivity()
	now = g.clock(now)
	g.gc(now)
	a.unlock()
	if err := g.rebuildProjection(now); err != nil {
		if l != nil {
			l.renewed = previous
		}
		old.persist, g.persist = l, nil
		old.wakePersistence()
		return err
	}
	a.lock()
	g.activity = a
	a.registry = g
	a.unlock()
	g.wakePersistence()
	return nil
}
