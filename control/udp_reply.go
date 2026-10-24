// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
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

func (s *udpReplySender) send(data []byte, from netip.AddrPort) error {
	cached := s.cached.Load()
	var socket *Anyfrom
	if cached != nil && cached.from == from && cached.socket.refreshIdleDeadline() {
		socket = cached.socket
	} else {
		var err error
		socket, _, err = s.pool.GetOrCreate(from, DefaultAnyfromCacheTTL)
		if err != nil {
			if tryRawUDPFallback(data, from, s.to, s.mark, "get-or-create", err) {
				return nil
			}
			return err
		}
		if cached == nil || cached.from == from {
			s.cached.CompareAndSwap(cached, &udpReplySocket{from, socket})
		}
	}
	_, err := socket.WriteToUDPAddrPortWithDeadline(data, s.to, time.Now().Add(consts.DefaultDNSTimeout))
	if err != nil && tryRawUDPFallback(data, from, s.to, s.mark, "write-to-udp", err) {
		return nil
	}
	return err
}

// trySend sends without waiting from an existing socket of from, the cached
// one or one the pool holds; a reply without one, or one the socket cannot
// take at once, needs send.
func (s *udpReplySender) trySend(data []byte, from netip.AddrPort) bool {
	cached := s.cached.Load()
	var socket *Anyfrom
	if cached != nil && cached.from == from && cached.socket.refreshIdleDeadline() {
		socket = cached.socket
	} else if socket = s.pool.TryGet(from); socket == nil {
		return false
	} else if cached == nil || cached.from == from {
		s.cached.CompareAndSwap(cached, &udpReplySocket{from, socket})
	}
	_, err, attempted := socket.tryWrite(data, s.to, time.Time{})
	return attempted && err == nil
}
