package direct

import (
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDirectDialerSetsTCPUserTimeout(t *testing.T) {
	const timeout = 30 * time.Second
	for _, multipath := range []bool{false, true} {
		t.Run(fmt.Sprintf("mptcp=%v", multipath), func(t *testing.T) {
			address := multipathTestListener(t, multipath)
			conn, err := NewDirectDialer(Option{Mptcp: multipath, UserTimeout: timeout}).DialContext(t.Context(), "tcp4", address)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			tcp := conn.(*net.TCPConn)
			if mptcpSocket(tcp) {
				return // The kernel rejects the option; the dial must still succeed.
			}
			raw, err := tcp.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			got := -1
			if err := raw.Control(func(fd uintptr) {
				got, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
			}); err != nil {
				t.Fatal(err)
			}
			if got != int(timeout.Milliseconds()) {
				t.Fatalf("TCP_USER_TIMEOUT = %dms, want %v", got, timeout)
			}
		})
	}
}
