//go:build !linux

package netproxy

import (
	"errors"
	"net"
	"net/netip"
)

// NewUDPSocket returns nil: sends that never wait need Linux.
func NewUDPSocket(*net.UDPConn) *UDPSocket { return nil }

// Send returns errors.ErrUnsupported: sends that never wait need Linux.
func (*UDPSocket) Send([]byte, netip.AddrPort) error { return errors.ErrUnsupported }
