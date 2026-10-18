// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

type domainMapUpdate func(ip netip.Addr, bump, routing []uint32) error

type domainBitmaps struct{ bump, routing []uint32 }

type domainMapEntry struct {
	ip netip.Addr
	domainBitmaps
}

func (b domainBitmaps) equal(other domainBitmaps) bool {
	return slices.Equal(b.bump, other.bump) && slices.Equal(b.routing, other.routing)
}

type domainPublication struct {
	due   time.Time
	force bool
}

type domainProjectionError struct{ cause error }

func (e *domainProjectionError) Error() string {
	return fmt.Sprintf("domain kernel projection is incomplete: %v", e.cause)
}
func (e *domainProjectionError) Unwrap() error { return e.cause }

type domainProjection struct {
	max         int
	resident    map[netip.Addr]domainBitmaps     // only successful kernel writes
	desired     map[netip.Addr]domainBitmaps     // immutable snapshots, at most max entries
	pending     map[netip.Addr]domainPublication // coalesced desired/installed difference, at most 2*max
	lastWarning time.Time
	lastFailure time.Time
	err         error
	force       bool
	update      domainMapUpdate
	batchUpdate func([]domainMapEntry) error
	remove      func(netip.Addr) error
}

func domainBitmapWords() int { return consts.MaxMatchSetLen / 32 }

func domainBitmapAllZero(bitmap []uint32) bool {
	for _, word := range bitmap {
		if word != 0 {
			return false
		}
	}
	return true
}

func (g *DomainRegistry) kernelRoutingBitmaps(ip netip.Addr) (bump, routing []uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ip = ip.Unmap()
	if installed, resident := g.kernel.resident[ip]; resident {
		return slices.Clone(installed.bump), slices.Clone(installed.routing)
	}
	return nil, nil
}

// rebuild is only needed when this IP's members change. Every retained member,
// including zero-bit domains, participates in AND. Reuse the IP's own buffers.
func (s *ipRecord) rebuild() {
	clear(s.bump)
	for i := range s.routing {
		s.routing[i] = ^uint32(0)
	}
	s.priority = time.Time{}
	for r, pair := range s.domains {
		for i, word := range r.bitmap {
			s.bump[i] |= word
			s.routing[i] &= word
		}
		if !domainBitmapAllZero(r.bitmap) && pair.retainUntil.After(s.priority) {
			s.priority = pair.retainUntil
		}
	}
}

// syncProjection folds only changed membership, then chooses kernel residents.
// Unchanged membership with increased resident priority needs no publication.
// Caller holds mu, including while writing the combined AND/OR map value.
func (g *DomainRegistry) syncProjection(changed map[netip.Addr]struct{}, reconsider bool, now time.Time) {
	for ip := range changed {
		if s := g.byIP[ip]; s != nil {
			s.rebuild()
		}
	}
	k := &g.kernel
	if !reconsider && len(k.desired)+len(changed) <= k.max {
		// Every possible new candidate fits. An incompletely filled projection
		// has no omitted candidates to backfill, so only changed IPs matter.
		for ip := range changed {
			if s := g.byIP[ip]; s != nil && !domainBitmapAllZero(s.bump) {
				k.want(ip, s, false)
			} else {
				k.want(ip, nil, false)
			}
		}
		k.publish(now)
		return
	}

	// Capacity changes are selected from cached IP summaries, never by folding
	// pairs again. Sort only when some candidates actually have to be omitted.
	states := make([]netip.Addr, 0, len(g.byIP))
	for ip, s := range g.byIP {
		if !domainBitmapAllZero(s.bump) {
			states = append(states, ip)
		}
	}
	if len(states) > k.max {
		slices.SortFunc(states, func(a, b netip.Addr) int {
			if c := g.byIP[b].priority.Compare(g.byIP[a].priority); c != 0 {
				return c
			}
			return a.Compare(b)
		})
	}
	desired := make(map[netip.Addr]struct{}, min(len(states), k.max))
	for _, ip := range states[:min(len(states), k.max)] {
		desired[ip] = struct{}{}
	}
	// Free slots before inserting replacements into the non-LRU map.
	for ip := range k.desired {
		if _, keep := desired[ip]; !keep {
			k.want(ip, nil, false)
		}
	}
	for ip := range desired {
		_, wasDesired := k.desired[ip]
		_, modified := changed[ip]
		if !wasDesired || modified {
			k.want(ip, g.byIP[ip], false)
		}
	}
	k.publish(now)
	if len(states) > k.max && (k.lastWarning.IsZero() || now.Sub(k.lastWarning) >= time.Minute) {
		k.lastWarning = now
		log.WithFields(log.Fields{"candidates": len(states), "resident": len(desired), "capacity": k.max}).Warn("Domain kernel capacity excludes IPs; domain routing and capture coverage is incomplete")
	}
}

func (k *domainProjection) want(ip netip.Addr, s *ipRecord, force bool) {
	force = force || k.force || k.pending[ip].force
	if s == nil {
		delete(k.desired, ip)
	} else {
		value := domainBitmaps{s.bump, s.routing}
		if old, ok := k.desired[ip]; !ok || !old.equal(value) {
			k.desired[ip] = domainBitmaps{slices.Clone(s.bump), slices.Clone(s.routing)}
		}
	}
	desired, want := k.desired[ip]
	installed, exists := k.resident[ip]
	if !want && !exists || !force && want && exists && desired.equal(installed) {
		delete(k.pending, ip)
		return
	}
	request := k.pending[ip]
	request.force = request.force || force
	k.pending[ip] = request
}

// Caller owns the registry lock. Remove before inserting, and retain old values
// on failure. The bounded queue holds only selected or actually installed IPs;
// later changes supersede earlier requests without allocating another job.
func (k *domainProjection) publish(now time.Time) {
	for _, removing := range []bool{true, false} {
		if !removing && k.force && k.batchUpdate != nil && len(k.pending) > 1 {
			k.publishBatch(now)
		}
		for ip, request := range k.pending {
			value, wanted := k.desired[ip]
			if removing == wanted || now.Before(request.due) {
				continue
			}
			var err error
			if wanted {
				if _, exists := k.resident[ip]; !exists && len(k.resident) >= k.max {
					continue // An unsuccessful removal still owns this slot.
				}
				err = k.update(ip, value.bump, value.routing)
			} else {
				err = k.remove(ip)
			}
			if err != nil {
				k.err = &domainProjectionError{err}
				request.due = now.Add(time.Second)
				k.pending[ip] = request
				if k.lastFailure.IsZero() || now.Sub(k.lastFailure) >= time.Minute {
					k.lastFailure = now
					log.WithError(err).WithField("ip", ip).Warn("Domain kernel publication failed; retaining installed state and retrying")
				}
				continue
			}
			if wanted {
				k.resident[ip] = value
			} else {
				delete(k.resident, ip)
			}
			delete(k.pending, ip)
		}
	}
	if len(k.pending) == 0 {
		k.err = nil
	}
}

// Batch only full reconstruction, after removals free any required slots.
// On any batch failure, scalar publication retries every unconfirmed entry:
// kernels may have applied a prefix, and updates are deliberately idempotent.
func (k *domainProjection) publishBatch(now time.Time) {
	const batchSize = 256
	batch := make([]domainMapEntry, 0, min(batchSize, len(k.pending)))
	remaining := k.max - len(k.resident)
	flush := func() bool {
		if err := k.batchUpdate(batch); err != nil {
			return false
		}
		for _, entry := range batch {
			k.resident[entry.ip] = entry.domainBitmaps
			delete(k.pending, entry.ip)
		}
		batch = batch[:0]
		return true
	}
	for ip, request := range k.pending {
		value, wanted := k.desired[ip]
		if !wanted || now.Before(request.due) {
			continue
		}
		if _, resident := k.resident[ip]; !resident {
			if remaining <= 0 {
				continue
			}
			remaining--
		}
		batch = append(batch, domainMapEntry{ip, value})
		if len(batch) == batchSize && !flush() {
			return
		}
	}
	if len(batch) != 0 {
		flush()
	}
}

// Cold restore and reload publish all current-rule summaries, even if an IP was
// already resident in the predecessor's kernel map.
func (g *DomainRegistry) rebuildProjection(now time.Time) error {
	changed := make(map[netip.Addr]struct{}, len(g.byIP))
	for ip := range g.byIP {
		changed[ip] = struct{}{}
	}
	g.kernel.force = true
	g.syncProjection(changed, true, now)
	g.kernel.force = false
	return g.kernel.err
}

func (g *DomainRegistry) retryProjection(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.kernel.publish(now)
	}
}
