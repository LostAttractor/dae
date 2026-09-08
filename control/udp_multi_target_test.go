package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vless"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

type udpMultiTargetParent struct{}

func (udpMultiTargetParent) DialContext(context.Context, string, string) (net.Conn, error) {
	c, s := net.Pipe()
	go func() { defer s.Close(); io.Copy(io.Discard, s) }()
	return c, nil
}
func (udpMultiTargetParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	panic("unexpected")
}
func TestUDPMultipleDestinationsKeepSourceLifetime(t *testing.T) {
	for name, constructor := range map[string]func(netproxy.Dialer, protocol.Header) (netproxy.Dialer, error){"vless": vless.NewDialer, "vmess": vmess.NewDialer} {
		t.Run(name, func(t *testing.T) {
			data, err := constructor(udpMultiTargetParent{}, protocol.Header{Password: "00000000-0000-0000-0000-000000000000", ProxyAddress: "proxy.test:443"})
			if err != nil {
				t.Fatal(err)
			}
			d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: data}), new(dialer.GlobalOption), &dialer.Property{Name: name}, false, t.Name())
			defer d.Close()
			first := netip.MustParseAddrPort("192.0.2.1:443")
			second := netip.MustParseAddrPort("192.0.2.2:443")
			src := netip.MustParseAddrPort("192.0.2.10:30000")
			pc, err := d.ListenPacket(context.Background(), first.String())
			if err != nil {
				t.Fatal(err)
			}
			p := new(UdpEndpointPool)
			defer p.closeAll()
			ue := &UdpEndpoint{conn: pc, dialer: d, NatTimeout: time.Minute, traffic: stats.DefaultStore.OpenConnection(stats.Path{}, false)}
			p.add(src, ue)
			c := &ControlPlane{udpEndpoints: p}
			if err := c.writeUDP(context.Background(), ue, src, first, []byte("first")); err != nil {
				t.Fatal(err)
			}
			// A retained association keeps its selected runtime after configuration retirement.
			_ = d.Close()
			err = c.writeUDP(context.Background(), ue, src, second, []byte("second"))
			_, exists := p.pool.Load(src)
			if err != nil || !exists {
				t.Fatalf("second destination ended a healthy source lifetime: err=%v endpoint_present=%v", err, exists)
			}
		})
	}
}
