// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"hash/maphash"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type activityConn struct {
	net.Conn
	observe func()
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.observe()
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.observe()
	}
	return n, err
}

// The transparent TCP ingress supplies an accepted TCP socket through the
// sniffer, so this adapter always preserves its CloseWrite capability.
type activitySniffer struct {
	sniffing.ConnSnifferInterface
	observe func()
}

func (c *activitySniffer) Read(p []byte) (int, error) {
	n, err := c.ConnSnifferInterface.Read(p)
	if n > 0 {
		c.observe()
	}
	return n, err
}

func (c *activitySniffer) Write(p []byte) (int, error) {
	n, err := c.ConnSnifferInterface.Write(p)
	if n > 0 {
		c.observe()
	}
	return n, err
}

func (c *activitySniffer) CloseWrite() error {
	return c.ConnSnifferInterface.(netproxy.CloseWriter).CloseWrite()
}

// domainActivityInterval bounds how often one connection or UDP destination
// queues continued I/O. Renewal may trail the latest I/O by at most this much.
const domainActivityInterval = time.Second

// domainActivityEpoch is a monotonic base for lock-free throttling.
var domainActivityEpoch = time.Now()

// domainActivityThrottle admits its first call, then at most one per interval
// across concurrent callers.
type domainActivityThrottle struct{ next atomic.Int64 } // offset from domainActivityEpoch

func (t *domainActivityThrottle) admit(now time.Time) bool {
	at := int64(now.Sub(domainActivityEpoch))
	due := t.next.Load()
	return at >= due && t.next.CompareAndSwap(due, at+int64(domainActivityInterval))
}

// Setup observes synchronously before creating this handle; continued I/O of
// the connection, in either direction or through splice sampling, is throttled.
func (a *domainActivity) connection(ip netip.Addr, domain string) func() {
	key := newDomainActivityKey(ip, domain)
	shard := maphash.Comparable(domainActivitySeed, key) % domainActivityShards
	var throttle domainActivityThrottle
	return func() {
		if now := time.Now(); throttle.admit(now) {
			a.enqueueShard(key, shard, now)
		}
	}
}

// A UDP source can address several destinations. Only the first sniffed
// destination owns the name; other targets refresh their IP evidence only.
func (ue *UdpEndpoint) observeDomain(dst netip.AddrPort) { ue.observeTarget(dst, true) }

// observeTarget observes dst. A target new to the endpoint is observed
// synchronously, which may wait for the registry; without flush it is left
// unobserved and observeTarget reports false.
func (ue *UdpEndpoint) observeTarget(dst netip.AddrPort, flush bool) bool {
	if ue.activity == nil {
		return true
	}
	domain := ""
	if dst == ue.firstDst {
		domain = ue.domain
	}
	at := time.Now()
	ue.mu.Lock()
	target, seen := ue.activityTargets[dst]
	if !seen && !flush {
		ue.mu.Unlock()
		return false
	}
	if !seen {
		if ue.activityTargets == nil {
			ue.activityTargets = make(map[netip.AddrPort]udpActivityTarget)
		}
		if len(ue.activityTargets) >= maxUDPDestinationsPerSource {
			var oldest netip.AddrPort
			var used time.Time
			for key, entry := range ue.activityTargets {
				if !oldest.IsValid() || entry.lastUsed.Before(used) {
					oldest, used = key, entry.lastUsed
				}
			}
			delete(ue.activityTargets, oldest)
		}
		target.key = newDomainActivityKey(dst.Addr(), domain)
	}
	target.lastUsed = at
	queue := !seen || at.Sub(target.queuedAt) >= domainActivityInterval
	if queue {
		target.queuedAt = at
	}
	ue.activityTargets[dst] = target
	ue.mu.Unlock()
	if !queue {
		return true
	}
	if g := ue.activity.enqueue(target.key, at); g != nil && !seen {
		g.flushActivity()
	}
	return true
}
