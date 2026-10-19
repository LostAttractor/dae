// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/dnscache"
)

// One process-wide budget bounds all entry paths and retired policy namespaces.
// Cache entries hold no resolver, dialer or control-plane references.
var internalDNSCache = dnscache.New(4096, 8<<20)
var resolverCacheScope atomic.Uint64

type dnsDialFunc func(context.Context, string, string) (net.Conn, error)

func cacheDNSDial(cache *dnscache.Cache, dial dnsDialFunc) dnsDialFunc {
	scope := strconv.FormatUint(resolverCacheScope.Add(1), 10) + "\x00"
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if network != "udp" && network != "tcp" {
			return dial(ctx, network, address)
		}
		c := &cachedDNSConn{ctx: ctx, dial: dial, network: network, address: address,
			exchange: resolverCacheExchange{cache: cache, scope: scope + network + "\x00" + address + "\x00"}}
		if network == "udp" {
			return &cachedDNSPacketConn{c}, nil
		}
		return c, nil
	}
}

// net.Resolver opens one transport per DNS exchange. Defer the real dial until
// its first complete query misses the cache. Further or fragmented writes use
// the original transport; this adapter does not implement DNS multiplexing.
type cachedDNSConn struct {
	ctx     context.Context
	dial    dnsDialFunc
	network string
	address string

	readMu, writeMu, dialMu sync.Mutex
	mu                      sync.Mutex
	conn                    net.Conn
	closed, written         bool
	readDeadline            time.Time
	writeDeadline           time.Time
	changed                 chan struct{}
	reply                   []byte
	exchange                resolverCacheExchange
	pending                 *pendingDNSDial
	frame                   []byte
}

func (c *cachedDNSConn) notifyLocked() {
	if c.changed != nil {
		close(c.changed)
		c.changed = nil
	}
}

func (c *cachedDNSConn) stateErrorLocked(deadline time.Time) error {
	if c.closed {
		return net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (c *cachedDNSConn) connect() (net.Conn, error) {
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	c.mu.Lock()
	if err := c.stateErrorLocked(c.writeDeadline); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if c.conn != nil {
		conn := c.conn
		c.mu.Unlock()
		return conn, nil
	}
	ctx, cancel := context.WithCancelCause(c.ctx)
	defer cancel(nil)
	c.pending = &pendingDNSDial{cancel: cancel}
	c.updateDialDeadlineLocked()
	c.mu.Unlock()
	conn, err := c.dial(ctx, c.network, c.address)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending.timer != nil {
		c.pending.timer.Stop()
	}
	c.pending = nil
	if cause := context.Cause(ctx); cause != nil {
		err = cause
	}
	if stateErr := c.stateErrorLocked(c.writeDeadline); stateErr != nil {
		err = stateErr
	}
	if err == nil {
		err = conn.SetReadDeadline(c.readDeadline)
	}
	if err == nil {
		err = conn.SetWriteDeadline(c.writeDeadline)
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	c.conn = conn
	c.notifyLocked()
	return conn, nil
}

// A pending dial is part of Write and must follow deadline changes too. The
// parent context usually already has net.Resolver's deadline, so ordinary
// lookups need no additional timer. A changed earlier deadline gets one timer.
type pendingDNSDial struct {
	cancel context.CancelCauseFunc
	timer  *time.Timer
}

func (c *cachedDNSConn) updateDialDeadlineLocked() {
	p := c.pending
	if p == nil {
		return
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	deadline := c.writeDeadline
	if deadline.IsZero() {
		return
	}
	if !time.Now().Before(deadline) {
		p.cancel(os.ErrDeadlineExceeded)
		return
	}
	if parent, ok := c.ctx.Deadline(); ok && !deadline.Before(parent) {
		return
	}
	if p.timer != nil {
		p.timer.Reset(time.Until(deadline))
		return
	}
	p.timer = time.AfterFunc(time.Until(deadline), func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		// A stopped timer's callback can already be running. Check both the
		// current attempt and current deadline before cancelling anything.
		if c.pending == p && !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
			p.cancel(os.ErrDeadlineExceeded)
		}
	})
}

func (c *cachedDNSConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if err := c.stateErrorLocked(c.writeDeadline); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	first := !c.written
	c.written = true
	c.exchange.query, c.frame = nil, nil
	if first {
		wire := p
		if c.network == "tcp" {
			if len(p) >= 2 && int(binary.BigEndian.Uint16(p)) == len(p)-2 {
				wire = p[2:]
			} else {
				wire = nil
			}
		}
		if reply := c.exchange.lookup(wire, c.network == "udp"); reply != nil {
			if c.network == "tcp" {
				reply = append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...)
			}
			c.reply = reply
			c.notifyLocked()
			c.mu.Unlock()
			return len(p), nil
		}
	}
	c.mu.Unlock()
	conn, err := c.connect()
	if err != nil {
		return 0, err
	}
	return conn.Write(p)
}

func (c *cachedDNSConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		c.mu.Lock()
		if err := c.stateErrorLocked(c.readDeadline); err != nil {
			c.mu.Unlock()
			return 0, err
		}
		if len(p) == 0 {
			c.mu.Unlock()
			return 0, nil
		}
		if len(c.reply) > 0 {
			n := copy(p, c.reply)
			c.reply = c.reply[n:]
			if c.network == "udp" {
				c.reply = nil
			}
			c.mu.Unlock()
			return n, nil
		}
		if conn := c.conn; conn != nil {
			c.mu.Unlock()
			n, err := conn.Read(p)
			if n > 0 && err == nil {
				c.observe(p[:n])
			}
			return n, err
		}
		if c.changed == nil {
			c.changed = make(chan struct{})
		}
		changed, deadline := c.changed, c.readDeadline
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-changed:
		case <-c.ctx.Done():
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *cachedDNSConn) observe(wire []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exchange.query == nil {
		return
	}
	if c.network == "tcp" {
		if len(c.frame)+len(wire) > 65537 {
			c.exchange.query, c.frame = nil, nil
			return
		}
		c.frame = append(c.frame, wire...)
		if len(c.frame) < 2 || len(c.frame) < 2+int(binary.BigEndian.Uint16(c.frame)) {
			return
		}
		wire = c.frame[2:]
	}
	if c.exchange.observe(wire) {
		c.frame = nil
	}
}

func (c *cachedDNSConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conn, pending := c.conn, c.pending
	c.reply, c.exchange.query, c.frame = nil, nil, nil
	c.notifyLocked()
	c.mu.Unlock()
	if pending != nil {
		pending.cancel(net.ErrClosed)
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *cachedDNSConn) SetDeadline(t time.Time) error      { return c.setDeadline(t, true, true) }
func (c *cachedDNSConn) SetReadDeadline(t time.Time) error  { return c.setDeadline(t, true, false) }
func (c *cachedDNSConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }

func (c *cachedDNSConn) setDeadline(t time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if read {
		c.readDeadline = t
	}
	if write {
		c.writeDeadline = t
		c.updateDialDeadlineLocked()
	}
	c.notifyLocked()
	if c.conn == nil {
		return nil
	}
	if read && write {
		return c.conn.SetDeadline(t)
	}
	if read {
		return c.conn.SetReadDeadline(t)
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *cachedDNSConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	if c.network == "udp" {
		return &net.UDPAddr{}
	}
	return &net.TCPAddr{}
}

func (c *cachedDNSConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	// Resolver callbacks always receive literal addresses, so this cannot DNS.
	if c.network == "udp" {
		addr, _ := net.ResolveUDPAddr("udp", c.address)
		return addr
	}
	addr, _ := net.ResolveTCPAddr("tcp", c.address)
	return addr
}

func (c *cachedDNSConn) SyscallConn() (syscall.RawConn, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	if raw, ok := conn.(syscall.Conn); ok {
		return raw.SyscallConn()
	}
	return nil, errors.ErrUnsupported
}

type cachedDNSPacketConn struct{ *cachedDNSConn }

func (c *cachedDNSPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}
func (c *cachedDNSPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
