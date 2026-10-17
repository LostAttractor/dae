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
	"github.com/daeuniverse/dae/pkg/outbound/transport/tls"
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

func TestV2RayOwnsRealityLifecycle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		parent := new(testParentDialer)
		var reality *tls.Reality
		wantErr := errors.New("protocol construction failed")
		setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Layer, error) {
			reality = next.(*tls.Reality)
			if fail {
				return netproxy.Layer{}, wantErr
			}
			return netproxy.Layer{Data: testProtocolDialer{}}, nil
		})
		config := V2Ray{Add: "proxy.example", Port: "443", Net: "tcp", Protocol: "vless", TLS: "reality", Fingerprint: "chrome", PublicKey: "YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortId: "0123456789abcdef"}
		layer, err := config.Build(new(dialer.ExtraOption), dialer.NewUpstream(parent))
		if fail != errors.Is(err, wantErr) || !fail && err != nil {
			t.Fatalf("Build: %v", err)
		}
		if !fail && len(layer.Resources) != 1 {
			t.Fatal("REALITY not registered with layer owner")
		}
		layer.Close()
		if _, err := reality.DialContext(t.Context(), "tcp", "target.example:443"); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("REALITY remained open: %v", err)
		}
		if parent.closeCalls != 0 {
			t.Fatal("REALITY closed borrowed upstream")
		}
	}
}
