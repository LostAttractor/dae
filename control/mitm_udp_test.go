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

func TestMITMUDPAssociationSelection(t *testing.T) {
	host := controlTestHost(t, surgeRoutingEngine(t, "service.example"), nil)
	source := netip.MustParseAddrPort("192.0.2.1:51000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	for _, test := range []struct {
		name     string
		outbound consts.OutboundIndex
		flags    uint8
	}{
		{"HTTP capture", consts.OutboundDirect, captureHTTP},
		{"destination capture", consts.OutboundDirect, captureDestination},
		{"ordinary proxy without DNS capture", consts.OutboundUserDefinedMin, 0},
		{"explicit bump without DNS capture", consts.OutboundControlPlaneRouting, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pool UdpEndpointPool
			t.Cleanup(pool.closeAll)
			plane := &ControlPlane{udpEndpoints: &pool, mitmHost: host}
			ordinaryConn := newTestPacketConn(false)
			ordinary := newUdpEndpoint(&UdpEndpointOptions{PacketConn: ordinaryConn, NatTimeout: time.Minute})
			fullCone := udpEndpointKey{Source: source}
			pool.add(fullCone, ordinary)
			initial := &packetSniff{domain: "service.example", quic: true, http3: true}
			var associated []udpEndpointKey
			for _, target := range []struct {
				destination netip.AddrPort
				ifindex     uint32
			}{
				{destination, 7},
				{netip.MustParseAddrPort("198.51.100.2:443"), 7},
				{destination, 8},
			} {
				result := bpfRoutingResult{Outbound: uint8(test.outbound), CaptureFlags: test.flags, Ifindex: target.ifindex, Mark: 37, Must: 1}
				originalResult := result
				key := plane.mitmUDPEndpointKey(source, target.destination, &result, initial)
				want := udpEndpointKey{Source: source, Destination: target.destination, Interface: target.ifindex}
				if key != want || result != originalResult {
					t.Fatalf("initial selected key=%+v route=%+v; want key=%+v and unchanged route", key, result, want)
				}
				if existing, ok := pool.Get(key); ok {
					t.Fatalf("new H3 association reused endpoint %p (ordinary=%p)", existing, ordinary)
				}
				ingress, server := newMITMPacketPair(source, target.destination)
				endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: ingress, NatTimeout: time.Minute})
				endpoint.mitm = true
				pool.add(key, endpoint)
				associated = append(associated, key)
				// Subsequent QUIC packets do not advertise ALPN. Keep using the
				// association even before the kernel observes its ownership entry.
				continued := plane.mitmUDPEndpointKey(source, target.destination, &result, &packetSniff{})
				selected, ok := pool.Get(continued)
				if continued != key || !ok || selected != endpoint {
					t.Fatalf("packet without ClientHello lost its association: key=%+v endpoint=%p", continued, selected)
				}
				if _, err := selected.conn.WriteTo([]byte("application data"), server.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				_ = server.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 32)
				if n, _, err := server.ReadFrom(buf); err != nil || string(buf[:n]) != "application data" {
					t.Fatalf("datagram reached the wrong association: %q, %v", buf[:n], err)
				}
			}
			for _, key := range associated {
				result := bpfRoutingResult{Ifindex: key.Interface}
				if continued := plane.mitmUDPEndpointKey(source, key.Destination, &result, &packetSniff{}); continued != key {
					t.Fatalf("another destination/interface replaced association %+v with %+v", key, continued)
				}
			}
			unknown := netip.MustParseAddrPort("203.0.113.1:443")
			if key := plane.mitmUDPEndpointKey(source, unknown, &bpfRoutingResult{Ifindex: 7}, &packetSniff{}); key != fullCone {
				t.Fatalf("unrelated UDP lost full-cone behavior: %+v", key)
			}
			if current, ok := pool.Get(fullCone); !ok || current != ordinary {
				t.Fatal("H3 association replaced the ordinary full-cone endpoint")
			}
			select {
			case <-ordinaryConn.writeStarted:
				t.Fatal("ordinary full-cone endpoint received an intercepted datagram")
			default:
			}
		})
	}
}

func TestMITMUDPDrainOnlyDeliversExactAssociation(t *testing.T) {
	var endpoints UdpEndpointPool
	t.Cleanup(endpoints.closeAll)
	source := netip.MustParseAddrPort("192.0.2.1:51000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	key := udpEndpointKey{Source: source, Destination: destination, Interface: 7}
	bridge, server := newMITMPacketPair(source, destination)
	target := newUdpEndpoint(&UdpEndpointOptions{PacketConn: bridge, NatTimeout: time.Minute})
	target.mitm = true
	target.traffic = stats.DefaultStore.OpenConnection(stats.Path{}, false)
	endpoints.add(key, target)
	ordinary := newTestPacketConn(false)
	endpoints.add(udpEndpointKey{Source: source}, newUdpEndpoint(&UdpEndpointOptions{PacketConn: ordinary, NatTimeout: time.Minute}))
	otherDestination := netip.MustParseAddrPort("198.51.100.2:443")
	nonMITMKey := udpEndpointKey{Source: source, Destination: otherDestination, Interface: 7}
	dnat := newTestPacketConn(false)
	endpoints.add(nonMITMKey, newUdpEndpoint(&UdpEndpointOptions{PacketConn: dnat, NatTimeout: time.Minute}))
	for _, missing := range []udpEndpointKey{
		{Source: source, Destination: destination, Interface: 8},
		{Source: source, Destination: netip.MustParseAddrPort("198.51.100.1:8443"), Interface: 7},
		{Source: netip.MustParseAddrPort("192.0.2.2:51000"), Destination: destination, Interface: 7},
		nonMITMKey,
	} {
		endpoints.deliverMITM(missing, []byte("wrong association"))
	}
	endpoints.deliverMITM(key, []byte("QUIC drain"))
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	if n, _, err := server.ReadFrom(buf); err != nil || string(buf[:n]) != "QUIC drain" {
		t.Fatalf("wrong drain delivery: %q, %v", buf[:n], err)
	}
	for _, conn := range []*testPacketConn{ordinary, dnat} {
		select {
		case <-conn.writeStarted:
			t.Error("retirement delivered packets to a non-MITM endpoint")
		default:
		}
	}
}

func TestMITMUDPAssociationRequiresHTTP3Scope(t *testing.T) {
	var pool UdpEndpointPool
	plane := &ControlPlane{udpEndpoints: &pool, mitmHost: controlTestHost(t, surgeRoutingEngine(t, "service.example"), nil)}
	source := netip.MustParseAddrPort("192.0.2.1:51000")
	for _, test := range []struct {
		name    string
		port    uint16
		sniffed packetSniff
	}{
		{"no ClientHello", 443, packetSniff{}},
		{"QUIC without h3 ALPN", 443, packetSniff{domain: "service.example", quic: true}},
		{"other hostname", 443, packetSniff{domain: "outside.example", quic: true, http3: true}},
		{"wrong port", 8443, packetSniff{domain: "service.example", quic: true, http3: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), test.port)
			result := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), Ifindex: 7}
			if key := plane.mitmUDPEndpointKey(source, destination, result, &test.sniffed); key != (udpEndpointKey{Source: source}) {
				t.Fatalf("unmatched packet received a scoped association: %+v", key)
			}
		})
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
			key := udpEndpointKey{Source: source, Destination: destination, Interface: 7}
			pool.add(key, endpoint)
			t.Cleanup(pool.closeAll)
			result := make(chan error, 1)
			go func() { result <- endpoint.run(&pool, key, destination) }()
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
