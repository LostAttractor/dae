package http

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
)

func TestHTTPURLPreservesTLSOptions(t *testing.T) {
	for _, sni := range []string{"", "proxy.example"} {
		for _, insecure := range []bool{false, true} {
			t.Run(fmt.Sprintf("sni=%s/insecure=%t", sni, insecure), func(t *testing.T) {
				original := HTTP{Protocol: "https", Server: "127.0.0.1", Port: 443, SNI: sni, AllowInsecure: insecure}
				parsed, err := ParseHTTPURL(original.ExportToURL())
				if err != nil || *parsed != original {
					t.Fatalf("TLS options did not survive URL export: %+v, %v", parsed, err)
				}
			})
		}
	}
}

type httpTestParent struct{ net.Dialer }

func (httpTestParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected UDP request")
}

func TestHTTPSInsecureWithoutSNI(t *testing.T) {
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	for _, insecure := range []bool{false, true} {
		t.Run(fmt.Sprint(insecure), func(t *testing.T) {
			builder, _, err := NewHTTP(server.URL + "?allowInsecure=" + fmt.Sprint(insecure))
			if err != nil {
				t.Fatal(err)
			}
			layer, err := builder.Build(&dialer.ExtraOption{TlsImplementation: "tls"}, dialer.NewUpstream(&httpTestParent{}))
			if err != nil {
				t.Fatal(err)
			}
			defer layer.Close()
			err = layer.Sessions[0].Connect(t.Context())
			if (err == nil) != insecure {
				t.Fatalf("self-signed TLS with allowInsecure=%t: %v", insecure, err)
			}
		})
	}
}
