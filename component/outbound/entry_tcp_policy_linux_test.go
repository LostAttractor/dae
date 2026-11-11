// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	"golang.org/x/sys/unix"
)

func TestEntryTCPPolicyDoesNotChangeDirectSockets(t *testing.T) {
	entry, err := new(PathSpec).entryDialer(new(dialer.GlobalOption), nil)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := new(PathSpec).entryResolver(new(dialer.GlobalOption))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		dial     func(context.Context, string, string) (net.Conn, error)
		interval int
		count    int
	}{
		{"entry", entry.DialContext, 5, 3},
		{"direct", direct.NewDirectDialer(direct.Option{}).DialContext, 15, 9},
		{"bootstrap", resolver.Dial, 15, 9},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config net.ListenConfig
			config.SetMultipathTCP(false)
			listener, err := config.Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := test.dial(t.Context(), "tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			raw, err := conn.(syscall.Conn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			for option, want := range map[int]int{
				unix.TCP_USER_TIMEOUT: 0, unix.TCP_KEEPIDLE: 15,
				unix.TCP_KEEPINTVL: test.interval, unix.TCP_KEEPCNT: test.count,
			} {
				var got int
				if controlErr := raw.Control(func(fd uintptr) { got, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, option) }); controlErr != nil {
					t.Fatal(controlErr)
				}
				if err != nil || got != want {
					t.Fatalf("TCP option %d = %d, %v; want %d", option, got, err, want)
				}
			}
			var maxRTO int
			if controlErr := raw.Control(func(fd uintptr) {
				maxRTO, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, 44) // TCP_RTO_MAX_MS
			}); controlErr != nil {
				t.Fatal(controlErr)
			}
			if !errors.Is(err, unix.ENOPROTOOPT) {
				if err != nil {
					t.Fatal(err)
				}
				want := 15000
				if test.name != "entry" {
					// The untouched listener inherits the namespace's native RTO.
					peerRaw, err := peer.(*net.TCPConn).SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					if controlErr := peerRaw.Control(func(fd uintptr) {
						want, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, 44)
					}); controlErr != nil {
						t.Fatal(controlErr)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if maxRTO != want {
					t.Fatalf("TCP_RTO_MAX_MS = %d, want %d", maxRTO, want)
				}
			}
			udp, err := test.dial(t.Context(), "udp4", listener.Addr().String())
			if err != nil {
				t.Fatalf("TCP policy reached UDP: %v", err)
			}
			_ = udp.Close()
		})
	}
}
