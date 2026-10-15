package netproxy

import (
	"fmt"
	"net"
	"net/netip"
)

type ProxyAddr struct {
	network string
	address string // can be domain:port or ip:port
}

func NewProxyAddr(network, address string) *ProxyAddr {
	return &ProxyAddr{network, address}
}

func (a *ProxyAddr) Network() string { return a.network }
func (a *ProxyAddr) String() string  { return a.address }

func NewAddr(network, address string) (addr net.Addr) {
	if addrport, err := netip.ParseAddrPort(address); err != nil {
		addr = NewProxyAddr("udp", address)
	} else {
		switch network {
		case "tcp":
			addr = net.TCPAddrFromAddrPort(addrport)
		case "udp":
			addr = net.UDPAddrFromAddrPort(addrport)
		default:
			panic(fmt.Sprintf("unknown network type: %v", network))
		}
	}
	return
}
