// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
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

func (a *domainActivity) connection(ip netip.Addr, domain string) func() {
	key := newDomainActivityKey(ip, domain)
	return func() { a.enqueue(key, time.Now()) }
}

// A UDP source can address several destinations. Only the first sniffed
// destination owns the name; other targets refresh their IP evidence only.
func (ue *UdpEndpoint) observeDomain(dst netip.AddrPort) {
	if ue.activity == nil {
		return
	}
	domain := ""
	if dst == ue.firstDst {
		domain = ue.domain
	}
	at := time.Now()
	ue.mu.Lock()
	key, seen := ue.activityTargets[dst]
	if !seen {
		if ue.activityTargets == nil {
			ue.activityTargets = make(map[netip.AddrPort]domainActivityKey)
		}
		key = newDomainActivityKey(dst.Addr(), domain)
		ue.activityTargets[dst] = key
	}
	ue.mu.Unlock()
	if g := ue.activity.enqueue(key, at); g != nil && !seen {
		g.flushActivity()
	}
}
