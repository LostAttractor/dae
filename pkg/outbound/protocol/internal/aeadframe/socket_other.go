//go:build !linux

package aeadframe

import "net"

// socket leaves wakeups at the platform default outside Linux.
type socket struct{}

func (*socket) demand(net.Conn, int) {}
