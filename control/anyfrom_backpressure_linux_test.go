// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// An unresolved neighbor holds datagrams against a deliberately tiny send
// buffer. All links, addresses and neighbor queues live in a private namespace.
func TestAnyfromBackpressureDeadlineAndClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for isolated socket backpressure")
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
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)})
	must(err)
	defer socket.Close()
	must(socket.SetWriteBuffer(4096))
	a := &Anyfrom{conn: socket, idleTTL: time.Hour}
	dst := (&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 54321}).AddrPort()
	data := make([]byte, 4096)
	blocked := false
	for range 64 {
		_, err, attempted := a.tryWrite(data, dst, time.Now().Add(time.Second))
		must(err)
		if !attempted {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("fixture failed to fill send buffer")
	}
	if _, err := a.WriteToUDPAddrPortWithDeadline(data, dst, time.Now().Add(30*time.Millisecond)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("congested deadline: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := a.WriteToUDPAddrPortWithDeadline(data, dst, time.Now().Add(10*time.Second))
		result <- err
	}()
	must(a.Close())
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed blocked send: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt pending write")
	}
}
