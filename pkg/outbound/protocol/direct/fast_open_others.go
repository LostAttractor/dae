//go:build !linux

package direct

import (
	"net"
	"syscall"
)

// setFastOpenConnect is a no-op: TCP_FASTOPEN_CONNECT is Linux-specific.
func setFastOpenConnect(syscall.RawConn) {}

func deferredConnect(conn *net.TCPConn) net.Conn { return conn }
