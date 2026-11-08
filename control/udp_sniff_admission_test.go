// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
)

// A sniffing source buffers its later datagrams without setup capacity; only
// the routing and dial that follow sniffing wait for it.
func TestUDPSniffingBuffersWithoutSetupCapacity(t *testing.T) {
	initials := splitQUICInitials(t)
	bindings := newRoutingLayoutTestMap(t, "udp_bindings_map", 8)
	decisions := newRoutingLayoutTestMap(t, "udp_routing_cache_map", 8)
	var endpoints UdpEndpointPool
	defer endpoints.closeAll()
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(udp) -> proxy"))
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("UDP association must use the selected packet dialer")
		return nil, net.ErrClosed
	})
	recorder := &destinationUDPRecorder{downloadTestDialer: unused}
	global := &dialer.GlobalOption{}
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: recorder}), global, &dialer.Property{Name: t.Name()}, false, "")
	group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
	defer group.Close()
	plane := &ControlPlane{udpEndpoints: &endpoints, routingMatcher: matcher, deviceRoutes: newTestDeviceRoutes(t),
		core:      &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{UdpBindingsMap: bindings, UdpRoutingCacheMap: decisions}}}},
		outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), group},
	}
	source, dst := netip.MustParseAddrPort("192.0.2.10:5000"), netip.MustParseAddrPort("192.0.2.20:443")
	result := &routingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), Ifindex: 7, ProfileId: matcher.defaultProfileID}
	send := func(packet []byte) {
		t.Helper()
		if err := plane.handlePkt(t.Context(), packet, source, dst, result); err != nil {
			t.Fatal(err)
		}
	}
	buffered := func() int {
		t.Helper()
		ue, ok := endpoints.Get(source)
		if !ok || ue.pending == nil {
			t.Fatal("the source is not sniffing")
		}
		return len(ue.pending.packets)
	}

	send(initials[0])
	if buffered() != 1 {
		t.Fatal("the first Initial did not wait for the rest of the ClientHello")
	}
	refused := dropSetupCapacity.Load()
	plane.udpSlowWork.Store(maxConcurrentUDPSlowWork)
	send(initials[1])
	if dropSetupCapacity.Load() != refused || buffered() != 2 || len(recorder.targets) != 0 {
		t.Fatalf("without capacity: dropped %d, buffered %d, dials %d; want the datagram buffered",
			dropSetupCapacity.Load()-refused, buffered(), len(recorder.targets))
	}
	plane.udpSlowWork.Store(0)
	send(initials[1])
	if len(recorder.targets) != 1 || plane.udpSlowWork.Load() != 0 {
		t.Fatalf("a retransmission did not complete the setup: dials %d", len(recorder.targets))
	}
}

// splitQUICInitials captures a client's first flight while its ClientHello,
// with a post-quantum key share, spans two Initial packets.
func splitQUICInitials(t *testing.T) [2][]byte {
	t.Helper()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := quic.Dial(ctx, client, server.LocalAddr(), &tls.Config{
			ServerName: "192.0.2.20", NextProtos: []string{"probe"},
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		}, &quic.Config{InitialPacketSize: 1200})
		if conn != nil {
			_ = conn.CloseWithError(0, "done")
		}
	}()
	defer func() { cancel(); <-done }()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var packets [2][]byte
	for i := range packets {
		packet := make([]byte, 65535)
		n, _, err := server.ReadFrom(packet)
		if err != nil {
			t.Fatal(err)
		}
		packets[i] = packet[:n]
	}
	return packets
}
