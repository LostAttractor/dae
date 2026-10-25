//go:build !linux

package direct

import "net"

// mptcpSocket reports false: only Linux has MPTCP sockets.
func mptcpSocket(*net.TCPConn) bool { return false }
