package direct

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// mptcpSocket reports whether conn is an MPTCP socket, also one that fell
// back to TCP. Go dials plain TCP itself when the kernel refuses MPTCP.
func mptcpSocket(conn *net.TCPConn) bool {
	raw, err := conn.SyscallConn()
	return err == nil && rawProtocol(raw) == unix.IPPROTO_MPTCP
}

func rawProtocol(c syscall.RawConn) int {
	protocol := -1
	_ = c.Control(func(fd uintptr) {
		protocol, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	})
	return protocol
}
