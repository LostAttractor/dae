// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

// Pipes keep all protocol I/O inside the fake clock. Exercise the actual TLS,
// ingress server and upstream transport across the former 30s / 60s cutoffs.
func TestMITMSlowHTTPExchange(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, scoped := range []bool{true, false} {
			if protocol == "h1" && !scoped {
				continue // Cross-host authorities are admitted only on HTTP/2 and HTTP/3.
			}
			for _, slow := range []string{"headers", "upload"} {
				t.Run(fmt.Sprintf("%s/scoped=%t/%s", protocol, scoped, slow), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						authority, roots := http3TestAuthority(t)
						p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com"), PreserveRoute: true}}},
							wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler { return next }}
						host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, Instance{Plugin: p})
						upstream := func(context.Context, string, string) (net.Conn, error) {
							client, peer := net.Pipe()
							listener := &singleConnListener{Conn: peer, done: make(chan struct{}), finished: make(chan struct{})}
							server := &http.Server{TLSConfig: authority.TLSConfig("example.com"), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								body, err := io.ReadAll(r.Body)
								if err != nil {
									t.Errorf("upstream upload: %v", err)
									return
								}
								if slow == "headers" {
									time.Sleep(32 * time.Second)
								}
								fmt.Fprintf(w, "read=%d", len(body))
							})}
							protocols := new(http.Protocols)
							protocols.SetHTTP1(true)
							protocols.SetHTTP2(protocol == "h2")
							server.Protocols = protocols
							t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
							go server.ServeTLS(listener, "", "")
							return client, nil
						}
						transport := &http.Transport{
							ForceAttemptHTTP2: protocol == "h2",
							TLSClientConfig:   &tls.Config{RootCAs: roots},
							DialContext: func(context.Context, string, string) (net.Conn, error) {
								client, peer := net.Pipe()
								t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
								go host.ServeConn(peer, plugin.Flow{Host: "example.com", Port: 443}, testUpstream(upstream))
								return client, nil
							},
						}
						defer transport.CloseIdleConnections()
						client := &http.Client{Transport: transport, Timeout: 2 * time.Minute}
						request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/slow", nil)
						if err != nil {
							t.Fatal(err)
						}
						if !scoped {
							request.Host = "outside.example.com"
						}
						want := "read=0"
						if slow == "upload" {
							reader, writer := io.Pipe()
							defer reader.Close()
							defer writer.Close()
							request.Body, request.ContentLength = reader, 64
							want = "read=64"
							go func() {
								defer writer.Close()
								for range 64 {
									time.Sleep(time.Second)
									if _, err := io.WriteString(writer, "x"); err != nil {
										return
									}
								}
							}()
						}
						response, err := client.Do(request)
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(response.Body)
						response.Body.Close()
						if err != nil || response.StatusCode != http.StatusOK || string(body) != want {
							t.Fatalf("status=%d body=%q error=%v; want %q", response.StatusCode, body, err, want)
						}
					})
				})
			}
		}
	}
}
