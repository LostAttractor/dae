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

type activitySnifferCloseWriter struct{ *activitySniffer }

func (c *activitySnifferCloseWriter) CloseWrite() error {
	return c.ConnSnifferInterface.(netproxy.CloseWriter).CloseWrite()
}

func withDomainActivity(conn sniffing.ConnSnifferInterface, observe func()) sniffing.ConnSnifferInterface {
	c := &activitySniffer{conn, observe}
	if _, ok := conn.(netproxy.CloseWriter); ok {
		return &activitySnifferCloseWriter{c}
	}
	return c
}

func (a *domainActivity) connection(ip netip.Addr, domain string) func() {
	return func() { a.observe(ip, domain, time.Now()) }
}

// A UDP source can address several destinations. Only the first sniffed
// destination owns the name; other targets refresh their IP evidence only.
func (ue *UdpEndpoint) observeDomain(dst netip.AddrPort) {
	domain := ""
	if dst == ue.firstDst {
		domain = ue.domain
	}
	ue.activity.observe(dst.Addr(), domain, time.Now())
}
