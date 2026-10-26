// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

type readyAdmissionPacketConn struct {
	*testPacketConn
	written chan struct{}
}

func (c *readyAdmissionPacketConn) TryWriteTo(data []byte, _ net.Addr) (int, error) {
	c.written <- struct{}{}
	return len(data), nil
}

func TestUDPSlowOperationsLeaveWorkersForReadySources(t *testing.T) {
	for _, kind := range []string{"new-destination", "blocking-write"} {
		t.Run(kind, func(t *testing.T) {
			endpoints := new(UdpEndpointPool)
			defer endpoints.closeAll()
			tasks := newUdpTaskPool(udpPacketWork.execute)
			defer tasks.close()
			defer tasks.interrupt()
			plane := &ControlPlane{ctx: t.Context(), udpTaskPool: tasks, udpEndpoints: endpoints}
			first, second := netip.MustParseAddrPort("192.0.2.1:443"), netip.MustParseAddrPort("192.0.2.2:443")
			dialed := make(chan context.Context, udpTaskMaxWorkers)
			var connections []*testPacketConn
			for i := range uint16(udpTaskMaxWorkers) {
				source := testUdpKey(30000 + i)
				conn := newTestPacketConn(kind == "blocking-write")
				connections = append(connections, conn)
				endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour})
				if kind == "new-destination" {
					endpoint.firstDst = first
					endpoint.packetDialer = blockingPacketDialer{dialed: dialed}
					endpoint.sockets = make(map[netip.AddrPort]*udpSocket)
					endpoint.destinations = map[netip.AddrPort]udpDestination{second: {second, time.Now()}}
				}
				endpoints.add(source, endpoint)
				if !tasks.emit([]byte("slow"), udpPacketWork{plane: plane, src: source, dst: second, deadline: time.Now().Add(time.Minute)}) {
					t.Fatal("slow packet rejected at ingress")
				}
			}
			written := make(chan struct{}, 1)
			fast := testUdpKey(32000)
			endpoints.add(fast, newUdpEndpoint(&UdpEndpointOptions{PacketConn: &readyAdmissionPacketConn{testPacketConn: newTestPacketConn(false), written: written}, NatTimeout: time.Hour}))
			if !tasks.emit([]byte("ready"), udpPacketWork{plane: plane, src: fast, dst: first, deadline: time.Now().Add(time.Minute)}) {
				t.Fatal("ready packet rejected at ingress")
			}
			select {
			case <-written:
			case <-time.After(time.Second):
				t.Fatal("slow operations occupied every worker; the ready source could not run")
			}
			tasks.interrupt()
			tasks.close()
			started := len(dialed)
			if kind == "blocking-write" {
				started = 0
				for _, conn := range connections {
					select {
					case <-conn.writeStarted:
						started++
					default:
					}
				}
			}
			if started == 0 || started > udpTaskMaxWorkers/4 {
				t.Fatalf("started %d slow operations, want 1..%d", started, udpTaskMaxWorkers/4)
			}
		})
	}
}
