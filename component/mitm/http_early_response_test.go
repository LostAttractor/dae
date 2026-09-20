// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A zero-DATA upload can keep its trailer block pending while waiting for a
// response. Admission/local responses and upstream headers must not wait for it.
func TestEmptyRequestTrailersAllowEarlyResponse(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		for _, destination := range []string{"upstream", "local", "local_unannounced"} {
			t.Run(protocol+"/"+destination, func(t *testing.T) {
				ca, roots := http3TestAuthority(t)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					_ = http.NewResponseController(w).Flush()
				})
				var tcp string
				var udp net.Addr
				if protocol == "h2" {
					server := httptest.NewUnstartedServer(handler)
					server.EnableHTTP2 = true
					server.TLS = ca.TLSConfig("example.com")
					server.TLS.NextProtos = []string{"h2"}
					server.StartTLS()
					t.Cleanup(server.Close)
					tcp = server.Listener.Addr().String()
				} else {
					udp = http3TestUpstream(t, ca.TLSConfig("example.com"), handler)
				}
				p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}}
				p.wrap = func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
					return func(e *plugin.Exchange) (*http.Response, error) {
						if destination != "upstream" {
							return &http.Response{StatusCode: 403, Header: make(http.Header), Body: http.NoBody}, nil
						}
						return next(e)
					}
				}
				host := testHost(t, Options{Authority: ca, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, Instance{Plugin: p})
				plan := func(*http.Request) (UpstreamPlan, error) {
					if destination != "upstream" {
						t.Error("local response selected an upstream")
					}
					return UpstreamPlan{Key: "ingress", Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", tcp)
					}, DialPacket: func(context.Context, string) (net.PacketConn, net.Addr, error) {
						conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
						return conn, udp, err
					}}, nil
				}
				client := authorityTestClient(t, host, roots, protocol, plan)
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				announced := destination != "local_unannounced"
				if protocol == "h3" {
					transport := client.Transport.(*http3.Transport)
					conn, err := transport.Dial(ctx, "example.com:443", &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"h3"}}, &quic.Config{})
					if err != nil {
						t.Fatal(err)
					}
					defer conn.CloseWithError(0, "test complete")
					stream, err := transport.NewClientConn(conn).OpenRequestStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					stream.SetReadDeadline(time.Now().Add(time.Second))
					r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/", nil)
					if announced {
						r.Trailer = http.Header{"X-Checksum": nil}
					}
					if err := stream.SendRequestHeader(r); err != nil {
						t.Fatal(err)
					}
					// Do not Close the upload until the response headers arrive.
					resp, err := stream.ReadResponse()
					if err != nil {
						t.Fatal(err)
					}
					stream.Close()
					resp.Body.Close()
					if resp.StatusCode != 403 {
						t.Fatalf("early status=%d", resp.StatusCode)
					}
					return
				}
				raw, err := client.Transport.(*http.Transport).DialContext(ctx, "tcp", "example.com:443")
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				conn := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"h2"}})
				if err := conn.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				io.WriteString(conn, http2.ClientPreface)
				framer := http2.NewFramer(conn, conn)
				framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				if err := framer.WriteSettings(); err != nil {
					t.Fatal(err)
				}
				var block bytes.Buffer
				encoder := hpack.NewEncoder(&block)
				fields := []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/"}, {Name: "content-length", Value: "0"}}
				if announced {
					fields = append(fields, hpack.HeaderField{Name: "trailer", Value: "X-Checksum"})
				}
				for _, field := range fields {
					if err := encoder.WriteField(field); err != nil {
						t.Fatal(err)
					}
				}
				if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
					t.Fatal(err)
				}
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						t.Fatal(fmt.Errorf("response waited for empty upload EOF: %w", err))
					}
					if headers, ok := frame.(*http2.MetaHeadersFrame); ok && headers.StreamID == 1 {
						if got := headers.PseudoValue("status"); got != "403" {
							t.Fatalf("early status=%s", got)
						}
						return
					}
				}
			})
		}
	}
}
