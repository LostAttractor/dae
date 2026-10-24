package aeadframe

import (
	"math"
	"net"
	"syscall"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

// minRaise is the least remaining need worth raising SO_RCVLOWAT for.
const minRaise = 4 << 10

// socket steers when reads of the reader's TCP socket wake up.
type socket struct {
	raw     syscall.RawConn  // nil until the connection exposes its socket
	control func(fd uintptr) // s.adjust, bound once
	need    int              // bytes the next read needs, for adjust
	lowat   int              // SO_RCVLOWAT last set; the kernel default is 1
	ceiling int              // SO_RCVLOWAT bound once the kernel resized for it
}

// demand runs before each read that needs need more bytes.
func (s *socket) demand(conn net.Conn, need int) {
	if s.raw == nil && !s.probe(conn) || need < minRaise && s.lowat <= need {
		return
	}
	s.need = need
	_ = s.raw.Control(s.control)
}

// probe runs until conn exposes its socket: adapters may turn transparent
// after their own handshake.
func (s *socket) probe(conn net.Conn) bool {
	tcp := netproxy.ReadSocket(conn)
	if tcp == nil {
		return false
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return false
	}
	s.raw, s.control, s.lowat, s.ceiling = raw, s.adjust, 1, math.MaxInt
	return true
}

// adjust moves SO_RCVLOWAT to the bytes still missing after the read takes
// what is queued, so the following read wakes once, when they have arrived.
// It never exceeds them, or the reader would wait for bytes the peer need not
// send. Below minRaise it only lowers: waking early there costs little.
func (s *socket) adjust(fd uintptr) {
	rest := s.need
	if rest >= minRaise {
		if queued, err := unix.IoctlGetInt(int(fd), unix.SIOCINQ); err == nil {
			if rest -= queued; rest <= 0 {
				return
			}
		}
	}
	if s.lowat > rest || rest >= minRaise && rest != s.lowat {
		s.set(int(fd), rest)
	}
}

// set moves SO_RCVLOWAT to v. A value below minRaise only follows a smaller
// need: it cannot make the kernel resize buffers for any plausible receive
// buffer, so it is set directly.
func (s *socket) set(fd, v int) {
	if v < minRaise {
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVLOWAT, v) == nil {
			s.lowat = v
		}
		return
	}
	if rcvbuf, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
		s.setCapped(fd, v, rcvbuf)
	}
}

// setCapped keeps SO_RCVLOWAT within a quarter of rcvbuf, the receive buffer
// read just before, so the queue can reach it: MPTCP sockets, including those
// fallen back to TCP, lack TCP's EPOLLIN escape for a small window. If the
// kernel still grew the buffer for v, MPTCP has clamped every subflow window
// to v (net/mptcp/sockopt.c) and v may never queue, so halve it for good.
func (s *socket) setCapped(fd, v, rcvbuf int) {
	v = min(v, rcvbuf/4, s.ceiling)
	if v == s.lowat || unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVLOWAT, v) != nil {
		return
	}
	s.lowat = v
	if grown, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil && grown > rcvbuf {
		s.ceiling = max(v/2, 1)
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVLOWAT, s.ceiling) == nil {
			s.lowat = s.ceiling
		}
	}
}
