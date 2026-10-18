// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

type udpTaskBenchmarkConn struct {
	net.PacketConn
	written chan struct{}
}

func (c *udpTaskBenchmarkConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	c.written <- struct{}{}
	return len(data), nil
}

// Include packet ownership, queue scheduling and the real established write
// path. The sink excludes network latency and requires no BPF privileges.
func BenchmarkUdpTaskPoolPacket(b *testing.B) {
	for _, size := range []int{64, 1500} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			conn := &udpTaskBenchmarkConn{PacketConn: newTestPacketConn(false), written: make(chan struct{})}
			endpoints := new(UdpEndpointPool)
			defer endpoints.closeAll()
			source, destination := testUdpKey(12348), netip.MustParseAddrPort("192.0.2.1:443")
			endpoints.add(source, newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour}))
			pool := newUdpTaskPool(udpPacketWork.execute)
			defer pool.close()
			plane := &ControlPlane{ctx: b.Context(), udpTaskPool: pool, udpEndpoints: endpoints}
			payload := make([]byte, size)
			b.ReportAllocs()
			for b.Loop() {
				work := udpPacketWork{plane: plane, src: source, dst: destination, deadline: time.Now().Add(consts.DefaultDialTimeout)}
				if !pool.emit(payload, work) {
					b.Fatal("packet rejected")
				}
				<-conn.written
			}
		})
	}
}
