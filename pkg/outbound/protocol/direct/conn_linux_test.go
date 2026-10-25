package direct

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func socketFullDrops() uint64 {
	for drop := range netproxy.Drops() {
		if drop.Reason() == "socket_full" {
			return drop.Load()
		}
	}
	panic("no socket_full counter")
}

// Datagrams waiting for an unresolved neighbor fill a socket's send buffer;
// then the next datagram is dropped at once and counted, by TryWriteTo and
// WriteTo alike, on unconnected and connected sockets. All links and
// addresses live in a private namespace.
func TestUDPFullSendBufferDropsWithoutWaiting(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for an isolated unresolved neighbor")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	isolated, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer isolated.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatal(err)
		}
	}()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sender"}, PeerName: "peer"}
	must(netlink.LinkAdd(link))
	peer, err := netlink.LinkByName("peer")
	must(err)
	must(netlink.LinkSetUp(link))
	must(netlink.LinkSetUp(peer))
	address, err := netlink.ParseAddr("192.0.2.1/24")
	must(err)
	must(netlink.AddrAdd(link, address))

	d := NewDirectDialer(Option{})
	to := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:9"))
	unconnected, err := d.ListenPacket(t.Context(), "")
	must(err)
	defer unconnected.Close()
	connected, err := d.DialContext(t.Context(), "udp", to.String())
	must(err)
	defer connected.Close()
	data := make([]byte, 1200)
	for _, tc := range []struct {
		name       string
		conn       interface{ SetWriteBuffer(int) error }
		try, write func() (int, error)
	}{
		{"unconnected", unconnected.(*PacketConn),
			func() (int, error) { return unconnected.(netproxy.NonBlockingWriter).TryWriteTo(data, to) },
			func() (int, error) { return unconnected.WriteTo(data, to) }},
		{"connected", connected.(*net.UDPConn),
			func() (int, error) { return netproxy.TryWrite(connected, data) },
			func() (int, error) { return netproxy.WriteDatagram(connected, data) }},
	} {
		must(tc.conn.SetWriteBuffer(4096))
		start, dropped := time.Now(), socketFullDrops()
		for i := 0; ; i++ {
			_, err := tc.try()
			if err == netproxy.ErrPacketDropped {
				break
			}
			if err != nil || i == 64 {
				t.Fatalf("%s: TryWriteTo = %v after %d sent, want a full send buffer", tc.name, err, i)
			}
		}
		if n, err := tc.write(); n != len(data) || err != nil {
			t.Fatalf("%s: WriteTo = %d, %v; want a datagram lost, not an error", tc.name, n, err)
		}
		// The neighbor's resolution gives up after seconds.
		if elapsed := time.Since(start); elapsed > time.Second || socketFullDrops()-dropped != 2 {
			t.Fatalf("%s: %d drops counted after %v; want 2 at once", tc.name, socketFullDrops()-dropped, elapsed)
		}
	}
}
