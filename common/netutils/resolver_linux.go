//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"net"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
)

func newMarkedDialer(mark uint32) (*net.Dialer, error) {
	return &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, int(mark))
		},
	}, nil
}
