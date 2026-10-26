// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// An unresolved neighbor holds datagrams against a deliberately tiny send
// buffer: replies are dropped, DNS responses wait until their deadline or a
// close. All links, addresses and neighbor queues live in a private namespace.
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
		err := a.trySend(data, dst)
		if errors.Is(err, syscall.EAGAIN) {
			blocked = true
			break
		}
		must(err)
	}
	if !blocked {
		t.Fatal("fixture failed to fill send buffer")
	}
	sender := &udpReplySender{to: dst}
	sender.cached.Store(&udpReplySocket{from: socket.LocalAddr().(*net.UDPAddr).AddrPort(), socket: a})
	// Both sending paths drop and count at once: no wait for the socket.
	dropped, start := dropReplySocketFull.Load(), time.Now()
	if err := sender.trySend(data, sender.cached.Load().from); !errors.Is(err, netproxy.ErrPacketDropped) || dropReplySocketFull.Load()-dropped != 1 || time.Since(start) > time.Second {
		t.Fatalf("trySend to a full socket = %v after %v with %d counted", err, time.Since(start), dropReplySocketFull.Load()-dropped)
	}
	dropped, start = dropReplySocketFull.Load(), time.Now()
	if err := sender.send(data, sender.cached.Load().from); !errors.Is(err, netproxy.ErrPacketDropped) || dropReplySocketFull.Load()-dropped != 1 || time.Since(start) > time.Second {
		t.Fatalf("send to a full socket = %v after %v with %d counted", err, time.Since(start), dropReplySocketFull.Load()-dropped)
	}
	// A pushed reply is already dropped, not copied for a slow-path retry.
	_, ue, pushed, _, _ := pushEndpoint(t)
	ue.replies = sender
	dropped = dropReplySocketFull.Load()
	failed, memoryDrops := dropReplySendFailed.Load(), dropDownloadMemory.Load()
	limit := udpPacketMemory.UseLimit(1)
	pushed.onPacket(data, sender.cached.Load().from)
	limit.Close()
	if drops := dropReplySocketFull.Load() - dropped; drops != 1 {
		t.Fatalf("pushed reply counted %d socket drops, want 1", drops)
	}
	if dropReplySendFailed.Load() != failed || dropDownloadMemory.Load() != memoryDrops {
		t.Fatal("pushed reply double-counted the drop or tried to copy it into backlog")
	}
	if got := stats.DefaultStore.Snapshot()[ue.statsPath].DownloadBytes; got != 0 || ue.IsClosed() {
		t.Fatalf("dropped push recorded %d downloaded bytes or ended the association", got)
	}
	// DNS responses still wait, bounded by their deadline.
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
