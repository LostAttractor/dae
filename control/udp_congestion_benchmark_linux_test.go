// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"crypto/aes"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	ss2022 "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Compare the excess-packet paths, not overall throughput: before socket
// nonblocking sends a stalled worker let its source FIFO reject these packets.
func BenchmarkUDPCongestedPacket(b *testing.B) {
	b.Run("source_fifo_full", func(b *testing.B) {
		tasks := newUdpTaskPool(udpPacketWork.execute)
		defer tasks.close()
		work := udpPacketWork{src: netip.MustParseAddrPort("192.0.2.1:1234")}
		tasks.queues[work.src] = &udpTaskQueue{key: work.src, pending: udpTaskQueueLength}
		payload := make([]byte, 1200)
		before := dropSourceQueue.Load()
		b.ReportAllocs()
		for b.Loop() {
			if tasks.emit(payload, work) {
				b.Fatal("full FIFO accepted a packet")
			}
		}
		if got := dropSourceQueue.Load() - before; got != uint64(b.N) {
			b.Fatalf("counted %d FIFO drops, want %d", got, b.N)
		}
	})
	for _, transport := range []string{"direct", "ss2022"} {
		b.Run(transport+"_socket_full", func(b *testing.B) {
			benchmarkUDPSocketFull(b, transport)
		})
	}
}

func benchmarkUDPSocketFull(b *testing.B, transport string) {
	if os.Geteuid() != 0 {
		b.Skip("root required for an isolated unresolved neighbor")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	must := func(err error) {
		b.Helper()
		if err != nil {
			b.Fatal(err)
		}
	}
	original, err := netns.Get()
	must(err)
	defer original.Close()
	isolated, err := netns.New()
	must(err)
	defer isolated.Close()
	defer func() { must(netns.Set(original)) }()
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sender"}, PeerName: "peer"}
	must(netlink.LinkAdd(link))
	peer, err := netlink.LinkByName("peer")
	must(err)
	must(netlink.LinkSetUp(link))
	must(netlink.LinkSetUp(peer))
	address, err := netlink.ParseAddr("192.0.2.1/24")
	must(err)
	must(netlink.AddrAdd(link, address))
	// Keep resolution pending even during long benchmark runs, in this netns only.
	must(os.WriteFile("/proc/sys/net/ipv4/neigh/sender/retrans_time_ms", []byte("3600000"), 0600))
	to := netip.MustParseAddrPort("192.0.2.2:8388")
	d := direct.NewDirectDialer(direct.Option{})
	var conn net.PacketConn
	if transport == "direct" {
		conn, err = d.ListenPacket(b.Context(), "")
		must(err)
		defer conn.Close()
		must(conn.(*direct.PacketConn).SetWriteBuffer(4096))
	} else {
		raw, err := d.DialContext(b.Context(), "udp", to.String())
		must(err)
		defer raw.Close()
		must(raw.(*net.UDPConn).SetWriteBuffer(4096))
		key := make([]byte, 16)
		block, err := aes.NewCipher(key)
		must(err)
		conn = ss2022.NewUdpConn(raw, ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"], block, block, [][]byte{key}, key)
	}
	payload := make([]byte, 1200)
	addr := net.UDPAddrFromAddrPort(to)
	for i := 0; ; i++ {
		_, err := netproxy.TryWriteTo(conn, payload, addr)
		if errors.Is(err, netproxy.ErrPacketDropped) {
			break
		}
		must(err)
		if i == 64 {
			b.Fatal("fixture did not fill the send buffer")
		}
	}
	endpoints := new(UdpEndpointPool)
	defer endpoints.closeAll()
	src := netip.MustParseAddrPort("192.0.2.1:1234")
	endpoints.add(src, &UdpEndpoint{conn: conn, firstDst: to, NatTimeout: time.Hour})
	tasks := newUdpTaskPool(udpPacketWork.execute)
	defer tasks.close()
	plane := &ControlPlane{ctx: b.Context(), udpEndpoints: endpoints, udpTaskPool: tasks}
	slot := new(udpWriteSlot)
	before := countedDrops("socket_full")
	b.ReportAllocs()
	for b.Loop() {
		if err := plane.handlePktUntil(tasks.ctx, time.Now().Add(netproxy.DialTimeout), slot, payload, src, to, nil); err != nil {
			b.Fatal(err)
		}
	}
	if got := countedDrops("socket_full") - before; got != uint64(b.N) {
		b.Fatalf("counted %d EAGAIN drops, want %d (every packet)", got, b.N)
	}
}
