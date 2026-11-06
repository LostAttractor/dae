// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"golang.org/x/sys/unix"
)

func TestEntryDialerTCPFastOpenOnlyOnPlainTCP(t *testing.T) {
	// Without net.ipv4.tcp_fastopen's client bit the kernel refuses the
	// option, and the dial must go on without it.
	data, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_fastopen")
	mode, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	var listen net.ListenConfig
	listen.SetMultipathTCP(false)
	listener, err := listen.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); _ = conn.Close() }()
		}
	}()
	for _, test := range []struct{ fastOpen, mptcp bool }{{false, false}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("tcp_fast_open=%v/mptcp=%v", test.fastOpen, test.mptcp), func(t *testing.T) {
			option := dialer.NewGlobalOption(&config.Global{TCPFastOpen: test.fastOpen, Mptcp: test.mptcp})
			// Without a pool, MPTCP dials every connection with MPTCP.
			base, err := (&PathSpec{IPVersion: 4}).entryDialer(option, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := base.DialContext(t.Context(), "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw, err := conn.(syscall.Conn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			protocol, fastOpen := 0, 0
			_ = raw.Control(func(fd uintptr) {
				protocol, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
				fastOpen, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT)
			})
			if want := test.fastOpen && mode&1 != 0 && protocol != unix.IPPROTO_MPTCP; (fastOpen == 1) != want {
				t.Fatalf("protocol %d: TCP_FASTOPEN_CONNECT = %d, want set %v", protocol, fastOpen, want)
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
				t.Fatalf("echo %q, %v", reply, err)
			}
		})
	}
}
