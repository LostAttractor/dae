package netproxy_test

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
	"github.com/daeuniverse/dae/pkg/outbound/transport/simpleobfs"
	daetls "github.com/daeuniverse/dae/pkg/outbound/transport/tls"
)

// SendSocket finds the carrier's TCP socket through every adapter a shared
// carrier is built of; one it missed would leave the carrier ungated.
func TestSendSocketLooksThroughCarrierAdapters(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tcp := conn.(*net.TCPConn)
	wrappers := map[string]func(net.Conn) net.Conn{
		"tracked":     func(c net.Conn) net.Conn { return netproxy.TrackConn(c, func() {}) },
		"shadowsocks": func(c net.Conn) net.Conn { return &shadowsocks.TCPConn{Conn: c} },
		"ss2022":      func(c net.Conn) net.Conn { return &shadowsocks_2022.TCPConn{Conn: c} },
		"http obfs":   func(c net.Conn) net.Conn { return &simpleobfs.HTTPObfs{Conn: c} },
		"tls obfs":    func(c net.Conn) net.Conn { return &simpleobfs.TLSObfs{Conn: c} },
		"tls":         func(c net.Conn) net.Conn { return tls.Client(c, &tls.Config{}) },
		"fragment":    func(c net.Conn) net.Conn { return daetls.NewFragmentConn(c, 0, 0, 0, 0) },
	}
	all := net.Conn(tcp)
	for name, wrap := range wrappers {
		if got := netproxy.SendSocket(wrap(tcp)); got != tcp {
			t.Errorf("%s: found %v", name, got)
		}
		all = wrap(all)
	}
	if netproxy.SendSocket(all) != tcp {
		t.Error("lost the socket through the chain of every adapter")
	}
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	if netproxy.SendSocket(&shadowsocks_2022.TCPConn{Conn: local}) != nil {
		t.Error("found a socket under a pipe")
	}
}
