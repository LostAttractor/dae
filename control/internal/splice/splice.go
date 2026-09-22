// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"net"
	"syscall"
)

// TCPConn exposes the raw socket and half-close operations required by splice.
type TCPConn interface {
	net.Conn
	syscall.Conn
	CloseWrite() error
}
