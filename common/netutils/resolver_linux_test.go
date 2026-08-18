//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func TestMarkedResolverDialAppliesSoMark(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	const mark = uint32(0x2345)
	resolver, err := newMarkedResolver(mark)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := resolver.Dial(context.Background(), "udp4", server.LocalAddr().String())
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
	if got != int(mark) {
		t.Fatalf("resolver socket SO_MARK = %#x, want %#x", got, mark)
	}
}

func TestInstallDefaultResolver(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() {
		defaultResolverState.Lock()
		net.DefaultResolver = original
		defaultResolverState.configured = false
		defaultResolverState.mark = 0
		defaultResolverState.Unlock()
	})

	if err := InstallDefaultResolver(consts.TproxyMark); err == nil {
		t.Fatal("InstallDefaultResolver accepted TproxyMark")
	}
	if net.DefaultResolver != original || defaultResolverState.configured {
		t.Fatal("invalid resolver mark changed global resolver state")
	}

	if err := InstallDefaultResolver(0); err != nil {
		t.Fatal(err)
	}
	configured := net.DefaultResolver
	if configured == original || !configured.PreferGo || configured.Dial == nil {
		t.Fatal("InstallDefaultResolver did not install the marked Go resolver")
	}
	if err := InstallDefaultResolver(common.InternalSoMarkFromDae); err != nil {
		t.Fatalf("same-mark configuration failed: %v", err)
	}
	if net.DefaultResolver != configured {
		t.Fatal("same-mark configuration replaced net.DefaultResolver")
	}
	if err := InstallDefaultResolver(0x3456); err == nil {
		t.Fatal("InstallDefaultResolver accepted a mark change")
	}
}
