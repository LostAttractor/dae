//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	outbound "github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/protocol/direct"
	"golang.org/x/sys/unix"
)

func TestMarkedResolverDialAppliesSoMark(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	const mark = uint32(0x2345)
	dialer, err := newMarkedDialer(mark)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"resolver", "direct-packet"} {
		t.Run(mode, func(t *testing.T) {
			var conn io.Closer
			var err error
			if mode == "resolver" {
				conn, err = dialer.DialContext(context.Background(), "udp4", server.LocalAddr().String())
			} else {
				conn, err = direct.NewDirectDialer(direct.Option{Mark: int(mark)}).ListenPacket(context.Background(), "")
			}
			checkResolverSocketMark(t, conn, err, int(mark))
		})
	}
}

func checkResolverSocketMark(t *testing.T, conn io.Closer, err error, mark int) {
	t.Helper()
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOPROTOOPT) {
			t.Skipf("SO_MARK is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer conn.Close()

	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		t.Fatalf("resolver connection type %T does not expose syscall.Conn", conn)
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var (
		got     int
		sockErr error
	)
	if err = raw.Control(func(fd uintptr) {
		got, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	if got != mark {
		t.Fatalf("resolver socket SO_MARK = %#x, want %#x", got, mark)
	}
}

func TestInstallDefaultResolver(t *testing.T) {
	original := net.DefaultResolver
	bootstrap := outbound.BootstrapResolver
	t.Cleanup(func() {
		net.DefaultResolver = original
		outbound.BootstrapResolver = bootstrap
	})

	if _, err := InstallDefaultResolver(consts.TproxyMark, ""); err == nil {
		t.Fatal("InstallDefaultResolver accepted TproxyMark")
	}
	if net.DefaultResolver != original || outbound.BootstrapResolver != bootstrap {
		t.Fatal("invalid resolver mark changed global resolver state")
	}

	r, err := InstallDefaultResolver(common.InternalSoMarkFromDae, "192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	configured := net.DefaultResolver
	if configured == original || !configured.PreferGo || configured.Dial == nil {
		t.Fatal("InstallDefaultResolver did not install the marked Go resolver")
	}
	r.SetRoute(nil)
	if net.DefaultResolver != configured {
		t.Fatal("policy update replaced net.DefaultResolver")
	}
	if outbound.BootstrapResolver != r.Bootstrap || r.Bootstrap == r.Resolver {
		t.Fatal("proxy bootstrap did not get its own resolver")
	}
}
