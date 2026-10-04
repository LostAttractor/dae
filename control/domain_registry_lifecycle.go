// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"slices"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

// Start is called once by the owner before publishing the registry. One worker
// owns activity batches, GC and saving; persistence starts after activation.
func (g *DomainRegistry) Start() {
	g.workerDone = make(chan struct{})
	go func() {
		defer close(g.workerDone)
		activity := time.NewTicker(time.Second)
		sweep := time.NewTicker(consts.DnsStateSweepInterval)
		save := time.NewTicker(time.Minute)
		defer activity.Stop()
		defer sweep.Stop()
		defer save.Stop()
		for {
			select {
			case <-g.stopCh:
				return
			case <-activity.C:
				g.flushActivity()
			case now := <-sweep.C:
				g.Sweep(now)
			case <-save.C:
				g.flushActivity()
				g.mu.Lock()
				path, dirty := g.diskPath, g.generation != g.savedGeneration
				g.mu.Unlock()
				if path != "" && dirty {
					if err := g.Save(path); err != nil {
						log.WithError(err).Warn("Save domain registry")
					}
				}
			}
		}
	}()
}

func (g *DomainRegistry) EnablePersistence(path string) {
	g.mu.Lock()
	g.diskPath = path
	g.mu.Unlock()
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
	a.mu.Lock()
	g.closed = true
	if a.registry == g {
		a.pending, g.activityBatch = g.activityBatch, a.pending
		a.registry = nil
	}
	a.mu.Unlock()
	// Only the queue's current owner takes a final batch. Closing a predecessor
	// must not drain activity destined for its successor.
	reconsider := g.applyActivity()
	g.syncProjection(g.gc(g.evaluatedAt), reconsider, g.evaluatedAt)
	path := g.diskPath
	g.mu.Unlock()
	defer close(g.closeDone)
	g.stopWorker()
	if path != "" {
		// Disk durability is best-effort, just like periodic saves. All writers
		// are stopped, so a save failure must not prevent in-memory reload adoption.
		if err := g.Save(path); err != nil {
			log.WithError(err).WithField("path", path).Warn("Save domain registry on shutdown")
		}
	}
	return nil
}

// installRecords is shared by cold restore and reload. Caller holds mu on a
// fresh registry and owns the supplied records; attach current-rule bitmaps and
// index their shared pairs using the maps allocated by the constructor.
func (g *DomainRegistry) installRecords(records map[string]*domainRecord, matchBitmap func(string) []uint32) {
	for name, r := range records {
		r.bitmap = slices.Clone(matchBitmap(name))
		for ip, pair := range r.addresses {
			g.addPair(r, ip, pair)
		}
	}
	g.byName = records
}

// ForkFrom publishes an independent projection without stopping old request
// handlers. Runtime serializes DNS delivery with this snapshot and fans later
// observations out to every serving generation using its own domain matcher.
func (g *DomainRegistry) ForkFrom(old *DomainRegistry, matchBitmap func(string) []uint32, now time.Time) {
	// Join the old periodic writer before the new registry can persist a snapshot.
	old.stopWorker()
	old.mu.Lock()
	defer old.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	reconsider := old.drainActivity()
	old.syncProjection(old.gc(old.evaluatedAt), reconsider, old.evaluatedAt)
	g.gcCount = old.gcCount
	records := make(map[string]*domainRecord, len(old.byName))
	for name, r := range old.byName {
		addresses := make(map[netip.Addr]*domainPair, len(r.addresses))
		for ip, pair := range r.addresses {
			addresses[ip] = &domainPair{retainUntil: pair.retainUntil}
		}
		records[name] = &domainRecord{addresses: addresses}
	}
	g.installRecords(records, matchBitmap)
	g.clock(old.evaluatedAt)
	a := old.activity
	a.mu.Lock()
	g.activity = a
	a.registry = g
	a.pending, g.activityBatch = g.activityBatch, a.pending
	a.mu.Unlock()
	g.applyActivity()
	now = g.clock(now)
	g.gc(now)
	g.rebuildProjection(now)
	old.diskPath = ""
	g.generation++
}
