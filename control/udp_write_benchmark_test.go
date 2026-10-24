// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// Exercise one established packet on a pool worker, from the source lock to
// the transport write, with the dispatcher's per-packet deadline. Sockets
// select the per-destination path used when routing has destination rules.
// Transport I/O and queue scheduling are excluded.
func BenchmarkUDPEstablishedPacket(b *testing.B) {
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
