// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
)

type domainDirectSource interface {
	setSlot(netip.Addr, uint64) error
	setSlots([][16]byte, []domainDirectSlot) error
	removeSlot(netip.Addr) error
	start(func([]domainDirectObservation)) error
	stop()
}

// A new membership gets a new token even when its resulting bitmap is equal.
// This keeps a queued observation from renewing a different set of DNS pairs.
func (g *DomainRegistry) wantProjection(ip netip.Addr, s *ipRecord, now time.Time) {
	g.kernel.want(ip, s, false)
	if g.direct == nil {
		return
	}
	if s == nil {
		g.writeDirectSlot(ip, 0, now)
	} else if _, pending := g.kernel.pending[ip]; !pending {
		g.enableDirect(ip, now)
	} else {
		// The previous token is ineligible while publication is pending.
		// The successful writer, not this request, will install its replacement.
		delete(g.directRetry, ip)
	}
}

func (g *DomainRegistry) enableDirect(ip netip.Addr, now time.Time) {
	if g.direct != nil {
		g.directSerial++
		g.writeDirectSlot(ip, g.directSerial, now)
	}
}

func (g *DomainRegistry) enableDirectBatch(batch []domainMapEntry, now time.Time) {
	if g.direct == nil {
		return
	}
	keys, slots := make([][16]byte, len(batch)), make([]domainDirectSlot, len(batch))
	for i, entry := range batch {
		g.directSerial++
		keys[i], slots[i].Token = entry.ip.As16(), g.directSerial
	}
	err := g.direct.setSlots(keys, slots)
	if g.directSlots == nil {
		g.directSlots = make(map[netip.Addr]domainDirectSlot, len(batch))
	}
	for i, entry := range batch {
		if err == nil {
			g.directSlots[entry.ip] = slots[i]
			delete(g.directRetry, entry.ip)
		} else {
			// A failed batch may have installed a prefix. Track even an
			// unconfirmed slot so a later deselection also removes it.
			g.directSlots[entry.ip] = domainDirectSlot{}
			g.writeDirectSlot(entry.ip, slots[i].Token, now)
		}
	}
}

func (g *DomainRegistry) writeDirectSlot(ip netip.Addr, token uint64, now time.Time) {
	var err error
	if token != 0 {
		err = g.direct.setSlot(ip, token)
	} else if _, installed := g.directSlots[ip]; installed {
		err = g.direct.removeSlot(ip)
	}
	if err != nil {
		if g.directRetry == nil {
			g.directRetry = make(map[netip.Addr]uint64)
		}
		g.directRetry[ip] = token
		g.warnDirect(now, err)
		return
	}
	delete(g.directRetry, ip)
	if token == 0 {
		delete(g.directSlots, ip)
	} else {
		if g.directSlots == nil {
			g.directSlots = make(map[netip.Addr]domainDirectSlot)
		}
		g.directSlots[ip] = domainDirectSlot{Token: token}
	}
}

func (g *DomainRegistry) warnDirect(now time.Time, err error) {
	if g.directWarning.IsZero() || now.Sub(g.directWarning) >= time.Minute {
		log.WithError(err).Warn("Kernel-direct domain activity unavailable; forwarding is unchanged")
		g.directWarning = now
	}
}

func (g *DomainRegistry) startDirect() {
	if g.direct != nil {
		if err := g.direct.start(g.observeDirect); err != nil {
			g.mu.Lock()
			g.warnDirect(time.Now(), err)
			g.mu.Unlock()
		}
	}
}

func (g *DomainRegistry) observeDirect(batch []domainDirectObservation) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	accepted := false
	for _, o := range batch {
		slot, installed := g.directSlots[o.ip]
		_, retry := g.directRetry[o.ip]
		_, resident := g.kernel.resident[o.ip]
		_, publishing := g.kernel.pending[o.ip]
		if !installed || retry || !resident || publishing || slot.Token != o.token || o.stamp <= slot.LastSeen {
			continue
		}
		slot.LastSeen = o.stamp
		g.directSlots[o.ip] = slot
		g.clock(o.at)
		g.touch(domainActivityKey{ip: o.ip}, o.at)
		accepted = true
	}
	if accepted {
		reconsider := g.drainActivity()
		g.syncProjection(g.gc(g.evaluatedAt), reconsider, g.evaluatedAt)
	}
}
