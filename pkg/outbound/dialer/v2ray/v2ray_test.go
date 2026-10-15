package v2ray

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	protocolhttp "github.com/daeuniverse/dae/pkg/outbound/protocol/http"
)

type testParentDialer struct {
	closeCalls int
}

func (*testParentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (*testParentDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (d *testParentDialer) Close() error {
	d.closeCalls++
	return nil
}

type testProtocolDialer struct{}

func (testProtocolDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (testProtocolDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func setProtocolCreator(t *testing.T, name string, creator protocol.LayerCreator) {
	t.Helper()
	previous, existed := protocol.Mapper[name]
	protocol.Mapper[name] = creator
	t.Cleanup(func() {
		if existed {
			protocol.Mapper[name] = previous
		} else {
			delete(protocol.Mapper, name)
		}
	})
}

func TestV2RayClosesConstructedHTTPTransportOnProtocolError(t *testing.T) {
	wantErr := errors.New("protocol construction failed")
	parent := new(testParentDialer)
	var transport *protocolhttp.HttpProxy
	setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Layer, error) {
		transport = next.(*protocolhttp.HttpProxy)
		return netproxy.Layer{}, wantErr
	})

	config := V2Ray{
		Add: "proxy.example", Port: "80", ID: "id", Net: "h2", Path: "/tunnel", Protocol: "vless",
	}
	if built, err := config.Build(new(dialer.ExtraOption), dialer.NewUpstream(parent)); !errors.Is(err, wantErr) || built.Data != nil {
		t.Fatalf("Build() = %#v, %v; want empty layer, %v", built, err, wantErr)
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "target.example:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("HTTP transport after failed build returned %v, want net.ErrClosed", err)
	}
	if parent.closeCalls != 0 {
		t.Fatalf("parent close calls = %d, want 0", parent.closeCalls)
	}
}
