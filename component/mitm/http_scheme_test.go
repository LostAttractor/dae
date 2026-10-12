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

func TestHTTPSRequestSchemeHandling(t *testing.T) {
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
			// HTTP/2 uses the intercepted HTTPS scheme, including its default
			// port. Explicit port changes must still be rejected, and later
			// requests on the same connection must remain usable.
			for _, target := range []string{
				"http://example.com:443/resource",
				"https://example.com:443/resource",
				"http://example.com/resource",
				"http://example.com:80/resource",
				"https://example.com:443/after",
			} {
				r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					t.Fatal(err)
				}
				before := calls.Load()
				wantReason := ""
				if r.URL.Scheme == "http" && protocol != "h2" {
					wantReason = "scheme_mismatch"
				} else if r.URL.Port() == "80" {
					wantReason = "authority_port_mismatch"
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
				if wantReason != "" {
					if resp.StatusCode != 421 || calls.Load() != before || entry.Data["reason"] != wantReason {
						t.Fatalf("%s: status=%d calls=%d log=%v, want rejection %s", target, resp.StatusCode, calls.Load(), entry.Data, wantReason)
					}
				} else if resp.StatusCode != 200 || calls.Load() != before+1 || string(body) != "https" || entry.Data["request_scheme"] != "https" {
					t.Fatalf("%s: status=%d calls=%d body=%q log=%v", target, resp.StatusCode, calls.Load(), body, entry.Data)
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

func TestHTTP2SchemeUsesInterceptedConnection(t *testing.T) {
	// Go releases differ in whether :scheme=http over TLS leaves Request.TLS
	// nil. Admission uses the intercepted connection, not that incidental field.
	for _, state := range []*tls.ConnectionState{nil, {HandshakeComplete: true}} {
		r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		r.ProtoMajor = 2
		r.URL.Scheme = ""
		r.TLS = state
		_, reason := admitRequestAuthority(r, "https", plugin.Flow{Host: "example.com", Port: 443})
		if reason != "" {
			t.Fatalf("TLS=%v: admission reason = %q", state, reason)
		}
	}
}
