package direct

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// setUserTimeout sets TCP_USER_TIMEOUT before connect. An MPTCP socket
// refuses it (ENOPROTOOPT) unless it falls back to one subflow, which
// dialTCP handles; negotiated MPTCP carriers rely on keepalive.
func setUserTimeout(c syscall.RawConn, timeout time.Duration) error {
	if rawProtocol(c) == unix.IPPROTO_MPTCP {
		return nil
	}
	return setsockoptUserTimeout(c, timeout)
}

func setsockoptUserTimeout(c syscall.RawConn, timeout time.Duration) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(timeout.Milliseconds()))
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("set TCP_USER_TIMEOUT: %w", sockErr)
	}
	return nil
}
