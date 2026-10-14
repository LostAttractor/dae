// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

type failedPacketDialer struct{ calls int }

func (*failedPacketDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("fixture dial failure")
}
func (d *failedPacketDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	d.calls++
	return nil, errors.New("fixture packet failure")
}

func TestFailedUDPFallbackIsNotEstablished(t *testing.T) {
	data := new(failedPacketDialer)
	option := new(dialer.GlobalOption)
	group := func(name string, checked bool, kind outbound.GroupKind) *outbound.DialerGroup {
		d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: data}), option, &dialer.Property{Name: name}, checked, name)
		g := outbound.NewDialerGroup(option, name, kind, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
		t.Cleanup(func() { _ = g.Close() })
		return g
	}
	direct := group("direct", false, outbound.GroupKindSingleAlwaysAlive)
	block := group("block", false, outbound.GroupKindInvisible)
	unavailable := group("unavailable", true, outbound.GroupKindSelector)
	pool := new(UdpEndpointPool)
	t.Cleanup(pool.closeAll)
	c := &ControlPlane{udpEndpoints: pool, outbounds: []*outbound.DialerGroup{direct, block, unavailable}, noConnectivityOutbound: consts.OutboundDirect}
	src, dst := netip.MustParseAddrPort("192.0.2.1:12345"), netip.MustParseAddrPort("198.51.100.1:443")
	endpoint := &UdpEndpoint{firstDst: dst, NatTimeout: time.Minute, pending: &udpSetup{routingResult: &routingResult{Outbound: 2, NoSniff: 1}, sniffer: sniffing.NewPacketSniffer(nil)}}
	before := stats.DefaultStore.DirectFallbackConnections()
	lock, _ := pool.UdpEndpointKeyLocker.Lock(src)
	pool.addLocked(src, endpoint)
	err := c.initializeUDP(t.Context(), endpoint, src, dst, []byte("packet"))
	pool.UdpEndpointKeyLocker.Unlock(src, lock)
	if data.calls != 1 || endpoint.conn != nil {
		t.Fatalf("fixture missed failed association: calls=%d conn=%v err=%v", data.calls, endpoint.conn, err)
	}
	if got := stats.DefaultStore.DirectFallbackConnections(); got != before {
		t.Fatalf("failed association added established fallback: before=%d after=%d err=%v", before, got, err)
	}
}
