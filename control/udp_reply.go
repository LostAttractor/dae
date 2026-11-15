// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type udpReplySocket struct {
	from   netip.AddrPort
	socket *Anyfrom
}

// Remember only the first reply address. Other peers still use the bounded-by-
// idle-time pool, avoiding per-packet cache churn on full-cone associations.
// This reference never prevents idle eviction or owns the socket's lifetime.
type udpReplySender struct {
	pool   *AnyfromPool
	to     netip.AddrPort
	mark   uint32
	cached atomic.Pointer[udpReplySocket]
}

// send sends a reply from a socket of from, creating one only if there is
// none. It never waits for a full socket: the reply is dropped and counted,
// and send returns netproxy.ErrPacketDropped.
func (s *udpReplySender) send(data []byte, from netip.AddrPort) error {
	socket, err := s.socket(from, true)
	if err != nil {
		if tryRawUDPFallback(data, from, s.to, s.mark, nil, "get-or-create", err) {
			return nil
		}
		return err
	}
	err = socket.trySend(data, s.to)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EAGAIN):
		dropReplySocketFull.Add(1)
		return netproxy.ErrPacketDropped
	case errors.Is(err, errors.ErrUnsupported):
		// shortcut: a zoned client address is sent to through net.UDPConn,
		// which waits for a full socket; resolve zones in UDPSocket if
		// link-local clients need it.
		_, err = socket.writeWithDeadline(data, s.to, time.Now().Add(consts.DefaultDNSTimeout))
	}
	if err != nil && tryRawUDPFallback(data, from, s.to, s.mark, nil, "write-to-udp", err) {
		return nil
	}
	return err
}

// trySend sends without waiting from an existing socket of from, dropping and
// counting a reply if it is full. Only replies needing send return errReplyWouldBlock.
func (s *udpReplySender) trySend(data []byte, from netip.AddrPort) error {
	socket, _ := s.socket(from, false)
	if socket == nil {
		return errReplyWouldBlock
	}
	switch err := socket.trySend(data, s.to); {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EAGAIN):
		dropReplySocketFull.Add(1)
		return netproxy.ErrPacketDropped
	default:
		return errReplyWouldBlock
	}
}

// socket returns the cached socket of from or one the pool holds, without
// waiting for the pool, and caches the first. Only with create does it wait
// for the pool and create a missing socket; otherwise it may return nil.
func (s *udpReplySender) socket(from netip.AddrPort, create bool) (*Anyfrom, error) {
	cached := s.cached.Load()
	if cached != nil && cached.from == from && cached.socket.refreshIdleDeadline() {
		return cached.socket, nil
	}
	socket := s.pool.TryGet(from)
	if socket == nil {
		if !create {
			return nil, nil
		}
		var err error
		if socket, _, err = s.pool.GetOrCreate(from, DefaultAnyfromCacheTTL); err != nil {
			return nil, err
		}
	}
	if cached == nil || cached.from == from {
		s.cached.CompareAndSwap(cached, &udpReplySocket{from, socket})
	}
	return socket, nil
}
