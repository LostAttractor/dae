package netproxy

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setUnsentLowat(raw syscall.RawConn, n int) error {
	var err error
	if controlErr := raw.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
	}); controlErr != nil {
		return controlErr
	}
	return err
}

// sendBuffer returns SO_SNDBUF, which TCP grows with the connection, or 0.
func sendBuffer(raw syscall.RawConn) (n int) {
	_ = raw.Control(func(fd uintptr) {
		n, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	})
	return n
}

// waitWritable returns once raw polls writable, or failed, and whether it
// had to wait: polling not writable sets SOCK_NOSPACE, so the netpoller is
// woken once it turns writable.
func waitWritable(raw syscall.RawConn) (waited bool, err error) {
	var pollErr error
	err = raw.Write(func(fd uintptr) bool {
		fds := [1]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		for {
			n, e := unix.Poll(fds[:], 0)
			if e == unix.EINTR {
				continue
			}
			pollErr = e
			if e != nil || n > 0 {
				return true // socket errors are reported by the following write
			}
			break
		}
		waited = true
		return false
	})
	if err == nil {
		err = pollErr
	}
	return waited, err
}
