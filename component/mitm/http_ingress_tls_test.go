// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

// Accepting fronted HTTP authorities must not weaken authentication of either
// the original ingress or an explicitly rewritten network target.
func TestDomainFrontingRejectsInvalidUpstreamTLS(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		for _, rewrite := range []bool{false, true} {
			for _, failure := range []string{"name", "untrusted", "expired"} {
				t.Run(fmt.Sprintf("%s/rewrite=%t/%s", protocol, rewrite, failure), func(t *testing.T) {
					authority, roots := http3TestAuthority(t)
					upstreamCA, upstreamRoots := http3TestAuthority(t)
					target := "example.com"
					if rewrite {
						target = "rewrite.example"
					}
					certName := target
					if failure == "name" {
						certName = "business.example" // Covers Host, not the network/TLS target.
					}
					cert, err := upstreamCA.ServerCertificate(certName)
					if err != nil {
						t.Fatal(err)
					}
					trust := &tls.Config{RootCAs: upstreamRoots}
					if failure == "untrusted" {
						trust.RootCAs = x509.NewCertPool()
					} else if failure == "expired" {
						trust.Time = func() time.Time { return cert.Leaf.NotAfter.Add(time.Minute) }
					}
					var calls atomic.Int32
					handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })
					cfg := &tls.Config{Certificates: []tls.Certificate{*cert}}
					var tcp string
					var udp net.Addr
					if protocol == "h2" {
						server := httptest.NewUnstartedServer(handler)
						server.EnableHTTP2, server.TLS = true, cfg
						server.StartTLS()
						t.Cleanup(server.Close)
						tcp = server.Listener.Addr().String()
					} else {
						udp = http3TestUpstream(t, cfg, handler)
					}
					p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("business.example")}}}}
					p.wrap = func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
						return func(e *plugin.Exchange) (*http.Response, error) {
							if rewrite {
								e.Request.URL.Host = target
							}
							return next(e)
						}
					}
					host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: trust}, Instance{Plugin: p})
					planner := func(r *http.Request) (UpstreamPlan, error) {
						if r.URL.Hostname() != target || r.Host != "business.example" {
							t.Errorf("network target / authority: %s / %s", r.URL.Host, r.Host)
						}
						return UpstreamPlan{Key: target, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, "tcp", tcp)
						}, DialPacket: func(context.Context, string) (net.PacketConn, net.Addr, error) {
							conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
							return conn, udp, err
						}}, nil
					}
					client := authorityTestClient(t, host, roots, protocol, planner)
					r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", nil)
					r.Host = "business.example"
					resp, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != http.StatusBadGateway || calls.Load() != 0 {
						t.Fatalf("invalid upstream reached HTTP: status=%d calls=%d", resp.StatusCode, calls.Load())
					}
				})
			}
		}
	}
}
