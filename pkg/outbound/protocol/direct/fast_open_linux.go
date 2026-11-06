package direct

import (
	"net"
	"sync/atomic"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var fastOpenReported atomic.Bool

func setFastOpenConnect(c syscall.RawConn) {
	// MPTCP Fast Open varies by kernel, and multipath memory learns from a
	// completed handshake.
	if rawProtocol(c) == unix.IPPROTO_MPTCP {
		return
	}
	var err error
	_ = c.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
	})
	// An optimization only: the socket keeps a normal handshake.
	if err != nil && fastOpenReported.CompareAndSwap(false, true) {
		log.WithError(err).Warn("TCP Fast Open unavailable; node connections use normal handshakes. EOPNOTSUPP means net.ipv4.tcp_fastopen lacks the client bit (1)")
	}
}

// deferredConnect wraps conn if its connect waits for the first write.
func deferredConnect(conn *net.TCPConn) net.Conn {
	raw, err := conn.SyscallConn()
	if err != nil {
		return conn
	}
	var state uint8
	_ = raw.Control(func(fd uintptr) {
		if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			state = info.State
		}
	})
	if state != unix.BPF_TCP_SYN_SENT {
		return conn
	}
	return &fastOpenConn{conn}
}

// fastOpenConn is a connection dialed before its SYN, which its first write
// sends. Linux disconnects a socket shut down in SYN_SENT, discarding the
// written request, so CloseWrite waits for the handshake to complete.
type fastOpenConn struct{ *net.TCPConn }

func (c *fastOpenConn) CloseWrite() error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	handshaking := func(fd uintptr) bool {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		// A SYN never sent (nothing written yet) has no handshake to wait for.
		return err == nil && info.State == unix.BPF_TCP_SYN_SENT && info.Segs_out > 0
	}
	var pending bool
	if err := raw.Control(func(fd uintptr) { pending = handshaking(fd) }); err != nil {
		return err
	}
	// Only a pending handshake waits, and so obeys the write deadline; an
	// established socket shuts down at once, as net.TCPConn does.
	if pending {
		// The socket turns writable when the handshake ends.
		if err := raw.Write(func(fd uintptr) bool { return !handshaking(fd) }); err != nil {
			return err
		}
	}
	return c.TCPConn.CloseWrite()
}

// ReadPassthrough exposes the socket to receive tuning; reads are unchanged.
func (c *fastOpenConn) ReadPassthrough() net.Conn { return c.TCPConn }

// TCPSocket keeps native-socket handling: the wrapper adds no framing.
func (c *fastOpenConn) TCPSocket() *net.TCPConn { return c.TCPConn }
