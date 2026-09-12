// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

// Start is called once by the owner before publishing the registry. One worker
// owns both periodic jobs; persistence is enabled only after activation commits.
func (g *DomainRegistry) Start() {
	g.workerDone = make(chan struct{})
	go func() {
		defer close(g.workerDone)
		sweep := time.NewTicker(consts.DnsStateSweepInterval)
		save := time.NewTicker(30 * time.Second)
		defer sweep.Stop()
		defer save.Stop()
		for {
			select {
			case <-g.stopCh:
				return
			case now := <-sweep.C:
				g.Sweep(now)
			case <-save.C:
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

func (g *DomainRegistry) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		<-g.closeDone
		return nil
	}
	g.closed = true
	done, path := g.workerDone, g.diskPath
	g.mu.Unlock()
	defer close(g.closeDone)
	close(g.stopCh)
	if done != nil {
		<-done
	}
	if path != "" {
		// Disk durability is best-effort, just like periodic saves. All writers
		// are stopped, so a save failure must not prevent in-memory reload adoption.
		if err := g.Save(path); err != nil {
			log.WithError(err).WithField("path", path).Warn("Save domain registry on shutdown")
		}
	}
	return nil
}

// installRecords is shared by cold restore and reload. Caller holds mu and owns
// the supplied records; only current-rule bitmaps are attached to them.
func (g *DomainRegistry) installRecords(records map[string]*domainRecord, matchBitmap func(string) []uint32) {
	g.nextGC = time.Time{}
	g.byIP = make(map[netip.Addr]*ipRecord)
	for name, r := range records {
		r.bitmap = slices.Clone(matchBitmap(name))
		for ip, pair := range r.addresses {
			g.addPair(r, ip, pair)
		}
	}
	g.byName = records
}

// AdoptFrom is called on the fresh successor after its predecessor has fully
// closed. The retired records are immutable; the activity lock owns the handoff.
func (g *DomainRegistry) AdoptFrom(old *DomainRegistry, matchBitmap func(string) []uint32, now time.Time) {
	a := old.activity
	a.mu.Lock()
	defer a.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	if old.evaluatedAt.After(now) {
		now = old.evaluatedAt
	}
	now = g.clock(now)
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
	// max(existing deadline, event time + window) is order-independent. Apply
	// all queued activity before GC; collected evidence cannot be recreated.
	for _, event := range a.pending {
		g.touch(event.key, event.at)
	}
	g.gc(now)
	g.kernel.resident = maps.Clone(old.kernel.resident)
	g.rebuildProjection(now)
	g.activity = a
	a.registry, a.pending, a.handoff = g, nil, false
	g.adopted = true
	g.generation++
}

func (g *DomainRegistry) Adopted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.adopted
}
