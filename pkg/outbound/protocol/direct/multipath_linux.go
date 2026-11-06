package direct

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func rawProtocol(c syscall.RawConn) int {
	protocol := -1
	_ = c.Control(func(fd uintptr) {
		protocol, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	})
	return protocol
}
