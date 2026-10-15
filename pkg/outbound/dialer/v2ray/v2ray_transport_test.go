package v2ray

import (
	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/transport/grpc"
	"testing"
)

func TestGRPCSecuritySelection(t *testing.T) {
	var transport *grpc.Dialer
	setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Layer, error) {
		transport = next.(*grpc.Dialer)
		return netproxy.Layer{Data: testProtocolDialer{}}, nil
	})
	for _, security := range []string{"none", "tls"} {
		t.Run(security, func(t *testing.T) {
			builder, _, err := NewV2Ray("vless://00000000-0000-0000-0000-000000000000@proxy.example:443?type=grpc&security=" + security + "&sni=tls.example&serviceName=custom")
			if err != nil {
				t.Fatal(err)
			}
			built, err := builder.Build(&dialer.ExtraOption{AllowInsecure: true}, dialer.NewUpstream(new(testParentDialer)))
			if err != nil {
				t.Fatal(err)
			}
			defer built.Close()
			if security == "none" {
				if transport.TLSConfig != nil {
					t.Fatal("plaintext requested but TLS enabled")
				}
			} else if transport.TLSConfig == nil || transport.TLSConfig.ServerName != "tls.example" || !transport.TLSConfig.InsecureSkipVerify {
				t.Fatalf("TLS config = %#v", transport.TLSConfig)
			}
		})
	}
}

func TestUnsupportedSecurityDoesNotFallBack(t *testing.T) {
	for _, tc := range []struct{ protocol, network, security string }{
		{"vless", "tcp", "utls"},
		{"vless", "ws", "reality"},
		{"vmess", "tcp", "reality"},
	} {
		config := &V2Ray{Protocol: tc.protocol, Add: "proxy.example", Port: "443", ID: "00000000-0000-0000-0000-000000000000", Net: tc.network, TLS: tc.security}
		built, err := config.Build(new(dialer.ExtraOption), dialer.NewUpstream(new(testParentDialer)))
		if err == nil {
			built.Close()
			t.Fatalf("unsupported %s/%s/%s accepted", tc.protocol, tc.network, tc.security)
		}
	}
}
