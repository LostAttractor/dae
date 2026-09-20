// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestHTTPSRejectsMismatchedScheme(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			ca, roots := http3TestAuthority(t)
			logger, _, ended := observationLogger()
			var calls atomic.Int32
			p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}},
				wrap: func(_ plugin.Flow, _ plugin.Handler) plugin.Handler {
					return func(e *plugin.Exchange) (*http.Response, error) {
						calls.Add(1)
						return response(e.Request.URL.Scheme), nil
					}
				}}
			h := testHost(t, Options{Authority: ca, Logger: logger}, Instance{Plugin: p})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			var send func(*http.Request) (*http.Response, error)
			if protocol == "h3" {
				client, _, _ := http3TestClient(t, h, roots, "example.com", nil)
				transport := client.Transport.(*http3.Transport)
				conn, err := transport.Dial(ctx, "example.com:443", &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"h3"}}, &quic.Config{})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.CloseWithError(0, "test complete")
				// ClientConn lets the test send :scheme=http on the fixed QUIC
				// connection, bypassing Transport's URL scheme restriction.
				send = transport.NewClientConn(conn).RoundTrip
			} else {
				client, _ := tcpDrainClient(t, h, roots, protocol, testUpstream(nil))
				dial := client.Transport.(*http.Transport).DialContext
				raw, err := dial(ctx, "tcp", "example.com:443")
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				alpn := "http/1.1"
				if protocol == "h2" {
					alpn = "h2"
				}
				conn := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{alpn}})
				if err := conn.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if protocol == "h2" {
					transport := &http2.Transport{AllowHTTP: true}
					cc, err := transport.NewClientConn(conn)
					if err != nil {
						t.Fatal(err)
					}
					defer cc.Close()
					send = cc.RoundTrip
				} else {
					reader := bufio.NewReader(conn)
					send = func(r *http.Request) (*http.Response, error) {
						if err := r.WriteProxy(conn); err != nil { // Absolute-form carries scheme.
							return nil, err
						}
						return http.ReadResponse(reader, r)
					}
				}
			}
			// A rejection must not poison the connection or reach middleware.
			for _, scheme := range []string{"http", "https"} {
				r, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://example.com:443/resource", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := send(r)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				entry := ended.next(t)
				if scheme == "http" {
					if resp.StatusCode != 421 || calls.Load() != 0 || entry.Data["reason"] != "scheme_mismatch" {
						t.Fatalf("scheme mismatch: status=%d calls=%d log=%v", resp.StatusCode, calls.Load(), entry.Data)
					}
				} else if resp.StatusCode != 200 || calls.Load() != 1 || string(body) != "https" {
					t.Fatalf("matched scheme: status=%d calls=%d body=%q", resp.StatusCode, calls.Load(), body)
				}
			}
		})
	}
}

func TestHTTPRequestSchemeAdmission(t *testing.T) {
	for _, protocol := range []int{1, 2, 3} {
		for _, target := range []string{"http://example.com:80/", "https://example.com:80/", "ftp://example.com:80/"} {
			t.Run(fmt.Sprintf("HTTP%d/%s", protocol, target), func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, target, nil)
				r.ProtoMajor = protocol
				_, reason := admitRequestAuthority(r, "http", plugin.Flow{Host: "example.com", Port: 80})
				want := "scheme_mismatch"
				if r.URL.Scheme == "http" {
					want = ""
				}
				if reason != want {
					t.Fatalf("admission reason = %q, want %q", reason, want)
				}
			})
		}
	}
}
