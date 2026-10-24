// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/internal/testutil"
)

func TestVerificationOrigins(t *testing.T) {
	for _, endpoint := range []string{
		"https://127.0.0.1:443", "http://127.0.0.1:80",
		"https://[::1]:443/", "http://[::1]:80/",
		"https://[0:0:0:0:0:0:0:1]:443",
		"https://[::ffff:127.0.0.1]:00443",
		"https://[0:0:0:0:0:FFFF:7F00:1]:08443",
		"https://127.0.0.1:9443", "http://127.0.0.1:8080",
	} {
		t.Run(endpoint, func(t *testing.T) {
			var challengeOrigin, virtualOrigin string
			var certificateProved, mitmProved bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/certificate/tests", "/api/device/mitm-tests":
					// The server derives the initiating origin when the SDK omits it.
					challengeOrigin = "http://" + strings.TrimSuffix(r.Host, ":80")
					if r.TLS != nil {
						challengeOrigin = "https://" + strings.TrimSuffix(r.Host, ":443")
					}
					w.WriteHeader(http.StatusCreated)
					if r.URL.Path == "/api/certificate/tests" {
						json.MarshalWrite(w, api.CertificateTest{ID: "ca-proof", CAFingerprint: "fingerprint"})
					} else {
						json.MarshalWrite(w, api.MITMTest{ID: "mitm-proof", CAFingerprint: "fingerprint", MITMEnabled: true, MITMURL: virtualOrigin + "/test/mitm-proof"})
					}
				case "/api/certificate/tests/ca-proof", "/test/mitm-proof":
					if r.TLS == nil || r.Header.Get("Origin") != challengeOrigin {
						http.Error(w, "proof origin differs from challenge: "+r.Header.Get("Origin"), http.StatusForbidden)
						return
					}
					if r.Header.Get("Authorization") != "" {
						t.Error("proof leaked API credentials")
					}
					if r.URL.Path == "/api/certificate/tests/ca-proof" {
						certificateProved = true
						json.MarshalWrite(w, api.CertificateTest{ID: "ca-proof", CAFingerprint: "fingerprint"})
					} else {
						mitmProved = true
						json.MarshalWrite(w, api.MITMTestProof{ID: "mitm-proof", CAFingerprint: "fingerprint"})
					}
				case "/api/certificate":
					json.MarshalWrite(w, api.Certificate{Fingerprint: "fingerprint", MITMTestOrigins: []string{virtualOrigin}})
				case "/api/device/mitm-tests/mitm-proof":
					json.MarshalWrite(w, api.MITMTest{ID: "mitm-proof", MITMObserved: mitmProved})
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			httpsServer := httptest.NewTLSServer(handler)
			defer httpsServer.Close()
			virtualOrigin = httpsServer.URL
			httpServer := httptest.NewServer(handler)
			defer httpServer.Close()
			options := Options{Endpoint: endpoint, RootCAs: testutil.TLSRoots(httpsServer)}
			if strings.HasPrefix(endpoint, "https:") {
				options.APIKey = "user-key"
			}
			c, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			// Exercise standard ports and IPv6 without reserving host ports 80/443.
			transport := c.http.Transport.(*http.Transport)
			transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", httpServer.Listener.Addr().String())
			}
			transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				config := transport.TLSClientConfig.Clone()
				config.ServerName = "127.0.0.1"
				return (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", httpsServer.Listener.Addr().String())
			}
			if _, err := c.VerifyCertificate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := c.VerifyMITM(t.Context()); err != nil {
				t.Fatal(err)
			}
			if !certificateProved || !mitmProved {
				t.Fatal("verification skipped a proof")
			}
		})
	}
}
