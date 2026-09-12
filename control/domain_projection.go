// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"slices"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

type domainMapUpdate func(ip netip.Addr, bump, routing []uint32)

type domainProjection struct {
	max         int
	resident    map[netip.Addr]struct{}
	lastWarning time.Time
	update      domainMapUpdate
	remove      func(netip.Addr)
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
	if _, resident := g.kernel.resident[ip]; resident {
		s := g.byIP[ip]
		return slices.Clone(s.bump), slices.Clone(s.routing)
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
	if !reconsider && len(k.resident)+len(changed) <= k.max {
		// Every possible new candidate fits. An incompletely filled projection
		// has no omitted candidates to backfill, so only changed IPs matter.
		for ip := range changed {
			if s := g.byIP[ip]; s != nil && !domainBitmapAllZero(s.bump) {
				k.update(ip, s.bump, s.routing)
				k.resident[ip] = struct{}{}
			} else if _, resident := k.resident[ip]; resident {
				k.remove(ip)
				delete(k.resident, ip)
			}
		}
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
	for ip := range k.resident {
		if _, keep := desired[ip]; !keep {
			k.remove(ip)
		}
	}
	for ip := range desired {
		_, wasResident := k.resident[ip]
		_, modified := changed[ip]
		if !wasResident || modified {
			s := g.byIP[ip]
			k.update(ip, s.bump, s.routing)
		}
	}
	k.resident = desired
	if len(states) > k.max && (k.lastWarning.IsZero() || now.Sub(k.lastWarning) >= time.Minute) {
		k.lastWarning = now
		log.WithFields(log.Fields{"candidates": len(states), "resident": len(desired), "capacity": k.max}).Warn("Domain kernel capacity excludes IPs; domain routing and capture coverage is incomplete")
	}
}

// Cold restore and reload publish all current-rule summaries, even if an IP was
// already resident in the predecessor's kernel map.
func (g *DomainRegistry) rebuildProjection(now time.Time) {
	changed := make(map[netip.Addr]struct{}, len(g.byIP))
	for ip := range g.byIP {
		changed[ip] = struct{}{}
	}
	g.syncProjection(changed, true, now)
}
