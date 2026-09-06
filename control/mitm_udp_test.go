// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestMITMUDPSourceKeepsSeparateDestinations(t *testing.T) {
	var endpoints UdpEndpointPool
	t.Cleanup(endpoints.closeAll)
	source := netip.MustParseAddrPort("192.0.2.1:51000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	bridge, server := newMITMPacketPair(source, destination)
	selected := &udpLifecycleDialer{opened: make(chan *udpLifecyclePacket, 8)}
	endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: bridge, NatTimeout: time.Minute})
	endpoint.mitm, endpoint.firstDst, endpoint.firstIfindex = true, destination, 7
	endpoint.packetDialer = selected
	endpoint.destinations = map[netip.AddrPort]netip.AddrPort{destination: destination}
	endpoint.sockets = map[netip.AddrPort]net.PacketConn{destination: bridge}
	endpoint.traffic = stats.DefaultStore.OpenConnection(stats.Path{}, false)
	endpoints.add(source, endpoint)
	plane := &ControlPlane{udpEndpoints: &endpoints}
	other := netip.MustParseAddrPort("198.51.100.2:443")
	// Existing sources do not reselect, even if a later packet carries a
	// different kernel route. Only the proven destination enters the bridge.
	for _, dst := range []netip.AddrPort{destination, other, destination} {
		if err := plane.handlePkt(t.Context(), []byte(dst.String()), source, dst, &bpfRoutingResult{Outbound: uint8(consts.OutboundBlock)}); err != nil {
			t.Fatal(err)
		}
	}
	ordinary := <-selected.opened
	if got := <-ordinary.writes; got != other {
		t.Fatalf("ordinary destination = %v, want %v", got, other)
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	for range 2 {
		buf := make([]byte, 64)
		if n, _, err := server.ReadFrom(buf); err != nil || string(buf[:n]) != destination.String() {
			t.Fatalf("bridge received another destination: %q, %v", buf[:n], err)
		}
	}
	if current, ok := endpoints.Get(source); !ok || current != endpoint || len(selected.opened) != 0 {
		t.Fatal("another destination replaced the source's lifetime")
	}
}

func TestMITMUDPDrainOnlyDeliversExactAssociation(t *testing.T) {
	var endpoints UdpEndpointPool
	t.Cleanup(endpoints.closeAll)
	source := netip.MustParseAddrPort("192.0.2.1:51000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	bridge, server := newMITMPacketPair(source, destination)
	target := newUdpEndpoint(&UdpEndpointOptions{PacketConn: bridge, NatTimeout: time.Minute})
	target.mitm, target.firstDst, target.firstIfindex = true, destination, 7
	target.traffic = stats.DefaultStore.OpenConnection(stats.Path{}, false)
	ordinary := newTestPacketConn(false)
	target.sockets = map[netip.AddrPort]net.PacketConn{destination: bridge, {}: ordinary}
	endpoints.add(source, target)
	for _, missing := range []struct {
		source, destination netip.AddrPort
		ifindex             uint32
	}{
		{source, destination, 8},
		{source, netip.MustParseAddrPort("198.51.100.1:8443"), 7},
		{netip.MustParseAddrPort("192.0.2.2:51000"), destination, 7},
	} {
		endpoints.deliverMITM(missing.source, missing.destination, missing.ifindex, []byte("wrong association"))
	}
	endpoints.deliverMITM(source, destination, 7, []byte("QUIC drain"))
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	if n, _, err := server.ReadFrom(buf); err != nil || string(buf[:n]) != "QUIC drain" {
		t.Fatalf("wrong drain delivery: %q, %v", buf[:n], err)
	}
	select {
	case <-ordinary.writeStarted:
		t.Error("retirement delivered packets to a non-MITM socket")
	default:
	}
}

func TestMITMUDPEndpointClose(t *testing.T) {
	source := netip.MustParseAddrPort("192.0.2.1:51000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	readFailure := errors.New("upstream read failed")
	for _, test := range []struct {
		name string
		mitm bool
		err  error
	}{
		{name: "closed HTTP3 bridge", mitm: true},
		{name: "ordinary UDP close", err: net.ErrClosed},
		{name: "HTTP3 other read failure", mitm: true, err: readFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			ingress, server := newMITMPacketPair(source, destination)
			t.Cleanup(func() { _ = ingress.Close() })
			conn := ingress
			if test.err == readFailure {
				conn = mitmUDPReadErrorConn{PacketConn: ingress, err: readFailure}
			}
			endpoint := newUdpEndpoint(&UdpEndpointOptions{
				PacketConn: conn, NatTimeout: time.Minute,
				Dialer: &dialer.Dialer{Property: &dialer.Property{Name: "selected"}},
				Path:   stats.Path{Network: common.NetworkUDP4},
			})
			endpoint.mitm = test.mitm
			var pool UdpEndpointPool
			key := source
			pool.add(key, endpoint)
			t.Cleanup(pool.closeAll)
			result := make(chan error, 1)
			go func() { result <- endpoint.run(&pool, key, destination, conn) }()
			// Host shutdown closes the bridge without retiring the endpoint;
			// this is also how a QUIC peer's normal disconnect is propagated.
			_ = server.Close()
			select {
			case err := <-result:
				if !errors.Is(err, test.err) {
					t.Fatalf("endpoint result = %v, want %v", err, test.err)
				}
			case <-time.After(time.Second):
				t.Fatal("closing the bridge did not release the UDP endpoint")
			}
			if endpoint.IsClosed() {
				t.Fatal("test retired the endpoint before exercising bridge closure")
			}
		})
	}
}

type mitmUDPReadErrorConn struct {
	net.PacketConn
	err error
}

func (c mitmUDPReadErrorConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, c.err
}
