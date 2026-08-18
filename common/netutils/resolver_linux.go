//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func newMarkedResolver(mark uint32) (*net.Resolver, error) {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			if mark != 0 {
				dialer.Control = func(_, _ string, c syscall.RawConn) error {
					var sockErr error
					if err := c.Control(func(fd uintptr) {
						sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
					}); err != nil {
						return err
					}
					return sockErr
				}
			}
			return dialer.DialContext(ctx, network, address)
		},
	}, nil
}
