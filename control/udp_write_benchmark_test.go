// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
)

// Exercise one established packet on a pool worker, from the source lock to
// the transport write, with the dispatcher's per-packet deadline. Sockets
// select the per-destination path used when routing has destination rules.
// Transport I/O and queue scheduling are excluded.
func BenchmarkUDPEstablishedPacket(b *testing.B) {
	b.Run("transport=direct", benchmarkUDPDirectPacket)
	for _, sockets := range []bool{false, true} {
		b.Run(fmt.Sprintf("sockets=%t", sockets), func(b *testing.B) {
			conn := newTestPacketConn(false)
			defer conn.Close()
			source := netip.MustParseAddrPort("192.0.2.1:1234")
			destination := netip.MustParseAddrPort("192.0.2.2:443")
			endpoints := new(UdpEndpointPool)
			defer endpoints.closeAll()
			endpoint := &UdpEndpoint{conn: conn, firstDst: destination, NatTimeout: time.Hour}
			if sockets {
				endpoint.sockets = map[netip.AddrPort]*udpSocket{{}: {conn: conn, lastUsed: time.Now()}}
				endpoint.destinations = map[netip.AddrPort]udpDestination{destination: {destination, time.Now()}}
			}
			endpoints.add(source, endpoint)
			tasks := newUdpTaskPool(udpPacketWork.execute)
			defer tasks.close()
			plane := &ControlPlane{ctx: b.Context(), udpEndpoints: endpoints, udpTaskPool: tasks}
			slot := new(udpWriteSlot)
			payload := make([]byte, 1200)
			b.ReportAllocs()
			for b.Loop() {
				deadline := time.Now().Add(consts.DefaultDialTimeout)
				if err := plane.handlePktUntil(tasks.ctx, deadline, slot, payload, source, destination, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The same through direct's own UDP socket to a loopback receiver that
// drains in the background, including the kernel send.
func benchmarkUDPDirectPacket(b *testing.B) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer receiver.Close()
	if err := receiver.SetReadBuffer(4 << 20); err != nil {
		b.Fatal(err)
	}
	go func() {
		buffer := make([]byte, 2048)
		for {
			if _, _, err := receiver.ReadFromUDPAddrPort(buffer); err != nil {
				return
			}
		}
	}()
	conn, err := direct.NewDirectDialer(direct.Option{}).ListenPacket(b.Context(), "")
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	source := netip.MustParseAddrPort("192.0.2.1:1234")
	destination := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	endpoints := new(UdpEndpointPool)
	defer endpoints.closeAll()
	endpoints.add(source, &UdpEndpoint{conn: conn, firstDst: destination, NatTimeout: time.Hour})
	tasks := newUdpTaskPool(udpPacketWork.execute)
	defer tasks.close()
	plane := &ControlPlane{ctx: b.Context(), udpEndpoints: endpoints, udpTaskPool: tasks}
	slot := new(udpWriteSlot)
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for b.Loop() {
		deadline := time.Now().Add(consts.DefaultDialTimeout)
		if err := plane.handlePktUntil(tasks.ctx, deadline, slot, payload, source, destination, nil); err != nil {
			b.Fatal(err)
		}
	}
}
