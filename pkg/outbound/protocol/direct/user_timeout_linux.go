package direct

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setUserTimeout(c syscall.RawConn, timeout time.Duration) error {
	// shortcut: MPTCP rejects TCP_USER_TIMEOUT (ENOPROTOOPT), so those carriers
	// rely on keepalive; set it per subflow if a kernel exposes that.
	if rawProtocol(c) == unix.IPPROTO_MPTCP {
		return nil
	}
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
