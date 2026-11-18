// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"hash/crc32"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
)

const domainCapacityBuckets = 256

// Budget the retained indexes, not the process heap. Shared names, IPs and
// bitmap reservations are charged once regardless of projection membership.
const domainPairMemory int64 = 128
const domainIPMemory int64 = 384

func domainNameMemory(name string, bitmap []uint32) int64 {
	nameBytes := (int64(len(name)) + 15) &^ 15
	return 384 + nameBytes + 4*int64(len(bitmap))
}

func domainIPBitmapMemory() int64 { return 4 * 4 * int64(domainBitmapWords()) }

func domainPairIPCost(ipExists, ipMatched, nameMatched bool) int64 {
	cost := domainPairMemory
	if !ipExists {
		cost += domainIPMemory
	}
	if !ipMatched && nameMatched {
		cost += domainIPBitmapMemory()
	}
	return cost
}

// A missed pair can invalidate the AND as well as the OR for its IP. Hash
// collisions cost coverage rather than letting the omission index grow too.
type domainCapacity struct {
	memoryUsed      int64
	memoryLimit     int64
	omittedPairs    uint64
	incomplete      [domainCapacityBuckets]time.Time
	incompleteCount int
	incompleteDue   time.Time // lower bound; extending an active bucket need not update it
	reselect        bool
	capacityWriting bool
	capacityPending bool // coalesce guard writes across a whole DNS or activity batch
	lastWarning     time.Time
}

func domainCapacityBucket(ip netip.Addr) int {
	key := ip.As16()
	return int(crc32.Checksum(key[:], domainCRC) % domainCapacityBuckets)
}

func (c *domainCapacity) projectable(ip netip.Addr) bool {
	return c.incompleteCount == 0 || c.incomplete[domainCapacityBucket(ip)].IsZero()
}

func (g *DomainRegistry) omitPair(ip netip.Addr, deadline, now time.Time) {
	g.omittedPairs++
	g.extendIncomplete(domainCapacityBucket(ip), deadline)
	if g.lastWarning.IsZero() || now.Sub(g.lastWarning) >= time.Minute {
		g.lastWarning = now
		log.WithFields(log.Fields{"limit_bytes": g.memoryLimit, "used_bytes": g.memoryUsed, "incomplete_buckets": g.incompleteCount}).Warn("Domain registry budget exhausted; omitting new DNS pairs and suppressing incomplete IP projections")
	}
}

func (g *DomainRegistry) extendIncomplete(bucket int, deadline time.Time) {
	old := g.incomplete[bucket]
	if !deadline.After(old) {
		return
	}
	if old.IsZero() {
		g.reselect = true
		g.incompleteCount++
		if g.incompleteDue.IsZero() || deadline.Before(g.incompleteDue) {
			g.incompleteDue = deadline
		}
	}
	g.incomplete[bucket] = deadline
	g.persistCapacity(bucket, deadline)
}

// Reindex on restore, fork or expiry, never on ordinary traffic.
func (c *domainCapacity) indexIncomplete() {
	c.incompleteCount, c.incompleteDue = 0, time.Time{}
	for _, until := range c.incomplete {
		if !until.IsZero() {
			c.incompleteCount++
			if c.incompleteDue.IsZero() || until.Before(c.incompleteDue) {
				c.incompleteDue = until
			}
		}
	}
}

func (c *domainCapacity) expireIncomplete(cutoff time.Time) {
	if c.incompleteCount == 0 || c.incompleteDue.After(cutoff) {
		return
	}
	for i, until := range c.incomplete {
		if !until.IsZero() && !until.After(cutoff) {
			c.incomplete[i] = time.Time{}
			c.reselect = true
		}
	}
	c.indexIncomplete()
}
