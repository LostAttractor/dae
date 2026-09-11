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
	resident    map[netip.Addr]*ipKernelState
	candidates  int
	lastWarning time.Time
	update      domainMapUpdate
	remove      func(netip.Addr)
}

type ipKernelState struct {
	ip       netip.Addr
	bump     []uint32
	routing  []uint32
	priority time.Time
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
	if s := g.kernel.resident[ip.Unmap()]; s != nil {
		return slices.Clone(s.bump), slices.Clone(s.routing)
	}
	return nil, nil
}

// reconcile derives complete IP states from the sole evidence index. Zero-bit
// domains participate in AND, but only relevant domains contribute to priority.
// Caller holds the registry lock, including while writing the kernel map.
func (k *domainProjection) reconcile(records map[string]*domainRecord, now time.Time) {
	byIP := make(map[netip.Addr]*ipKernelState)
	for _, r := range records {
		relevant := !domainBitmapAllZero(r.bitmap)
		for ip, deadline := range r.addresses {
			s := byIP[ip]
			if s == nil {
				s = &ipKernelState{ip: ip, bump: make([]uint32, domainBitmapWords()), routing: slices.Clone(r.bitmap)}
				byIP[ip] = s
			}
			for i, word := range r.bitmap {
				s.bump[i] |= word
				s.routing[i] &= word
			}
			if relevant && deadline.After(s.priority) {
				s.priority = deadline
			}
		}
	}
	states := make([]*ipKernelState, 0, len(byIP))
	for _, s := range byIP {
		if !domainBitmapAllZero(s.bump) {
			states = append(states, s)
		}
	}
	k.candidates = len(states)
	slices.SortFunc(states, func(a, b *ipKernelState) int {
		if c := b.priority.Compare(a.priority); c != 0 {
			return c
		}
		return a.ip.Compare(b.ip)
	})
	desired := make(map[netip.Addr]*ipKernelState, min(len(states), k.max))
	for _, s := range states[:min(len(states), k.max)] {
		desired[s.ip] = s
	}
	// Free slots before inserting replacements into the non-LRU map.
	for ip := range k.resident {
		if desired[ip] == nil {
			k.remove(ip)
		}
	}
	for ip, s := range desired {
		old := k.resident[ip]
		if old == nil || !slices.Equal(old.bump, s.bump) || !slices.Equal(old.routing, s.routing) {
			k.update(ip, s.bump, s.routing)
		}
	}
	k.resident = desired
	if k.candidates > k.max && (k.lastWarning.IsZero() || now.Sub(k.lastWarning) >= time.Minute) {
		k.lastWarning = now
		log.WithFields(log.Fields{"candidates": k.candidates, "resident": len(desired), "capacity": k.max}).Warn("Domain kernel capacity excludes IPs; domain routing and capture coverage is incomplete")
	}
}
