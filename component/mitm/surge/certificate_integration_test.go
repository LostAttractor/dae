// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Response-only modules such as Bilibili Helper / AD, and request scripts alike,
// use single-host certificates. Fronted out-of-scope requests skip scripts.
func TestProxyCertificateIndependentOfScriptPhase(t *testing.T) {
	for _, phase := range []string{"http-request", "http-response"} {
		t.Run(phase, func(t *testing.T) {
			source := `$done({body: $response.body + "-script"});`
			if phase == "http-request" {
				source = `$done({body: $request.body + "-script"});`
			}
			engine, roots := integrationEngine(t, map[string]string{phase: source}, nil)
			engine.hostOptions.UpstreamTLSConfig = &tls.Config{RootCAs: roots}
			cert, err := engine.hostOptions.Authority.ServerCertificate("example.com")
			if err != nil {
				t.Fatal(err)
			}
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.ServerName != "example.com" {
					t.Errorf("upstream identity: SNI=%s Host=%s", r.TLS.ServerName, r.Host)
				}
				io.Copy(w, r.Body)
			}))
			upstream.EnableHTTP2 = true
			upstream.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
			upstream.StartTLS()
			t.Cleanup(upstream.Close)
			client := integrationClient(t, engine, roots, func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			}, true)
			for _, host := range []string{"example.com", "outside.example"} {
				r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/", strings.NewReader("payload"))
				if err != nil {
					t.Fatal(err)
				}
				r.Host = host
				resp, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				want := "payload"
				if host == "example.com" {
					want += "-script"
				}
				if err != nil || resp.StatusCode != 200 || resp.ProtoMajor != 2 || string(body) != want {
					t.Fatalf("%s: status=%d protocol=%s body=%q read=%v", host, resp.StatusCode, resp.Proto, body, err)
				}
				if resp.TLS.PeerCertificates[0].VerifyHostname("outside.example") == nil {
					t.Fatal("unexpected multi-host downstream certificate")
				}
			}
		})
	}
}
