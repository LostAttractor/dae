// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/component/ca"
	mitmverify "github.com/daeuniverse/dae/component/mitm/verify"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestVerificationOriginsWithAPIHandler(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "pki")
	authority, err := ca.Ensure(directory)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.ReadCertificate(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	targets, err := mitmverify.ParseTargets("", "")
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	for _, test := range []struct {
		name, listen, host, portPrefix string
	}{
		{"IPv4", "127.0.0.1:0", "127.0.0.1", ""},
		{"IPv4 padded port", "127.0.0.1:0", "127.0.0.1", "00"},
		{"IPv6", "[::1]:0", "::1", ""},
		{"expanded IPv6", "[::1]:0", "0:0:0:0:0:0:0:1", ""},
		{"mapped IPv6", "127.0.0.1:0", "::ffff:127.0.0.1", ""},
		{"uppercase expanded IPv6 padded port", "127.0.0.1:0", "0:0:0:0:0:FFFF:7F00:1", "00"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, err := mitmverify.New(authority.Fingerprint(), targets, nil)
			if err != nil {
				t.Fatal(err)
			}
			server, err := Listen("tcp", test.listen)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			identity := authority.Identity()
			identity.MITMTestOrigins = service.Origins()
			handler := NewHandler(Options{
				UserKey: "user-key", MITMTests: service, Devices: verificationDevices{},
				Certificates: &Certificates{Identity: identity, Handler: authority.Handler()},
				ResolveClient: func(netip.AddrPort, netip.AddrPort) (api.ClientIdentity, error) {
					return api.ClientIdentity{LinkType: "ethernet", MAC: mac}, nil
				},
			})
			server.Configure(handler, authority, t.TempDir())

			target := targets[0]
			if server.Addr().(*net.TCPAddr).AddrPort().Addr().Is6() {
				target = targets[1]
			}
			leaf, err := authority.ServerCertificate(target.String())
			if err != nil {
				t.Fatal(err)
			}
			virtual := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("MITM proof leaked API credentials")
				}
				// Supply the flow evidence normally attached by transparent interception.
				r.URL.Scheme = "https"
				flow := plugin.Flow{Host: target.String(), Port: 443, SourceMAC: mac, Destination: netip.AddrPortFrom(target, 443)}
				result, err := service.Wrap(flow, nil)(&plugin.Exchange{Request: plugin.NewRequest(r, nil)})
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer result.Close()
				response, _, err := result.TakeHTTP()
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer response.Body.Close()
				for key, values := range response.Header {
					w.Header()[key] = values
				}
				w.WriteHeader(response.StatusCode)
				if _, err := io.Copy(w, response.Body); err != nil {
					t.Error(err)
				}
			}))
			virtual.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
			virtual.StartTLS()
			defer virtual.Close()

			_, port, err := net.SplitHostPort(server.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			endpoint := "https://" + net.JoinHostPort(test.host, test.portPrefix+port)
			c, err := client.New(client.Options{Endpoint: endpoint, APIKey: "user-key", RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Certificate(t.Context()); err != nil {
				t.Fatal("ordinary HTTPS request:", err)
			}
			if proof, err := c.VerifyCertificate(t.Context()); err != nil || proof.CAFingerprint != authority.Fingerprint() {
				t.Fatal("certificate proof:", proof, err)
			}
			mitmTest, err := c.StartMITMTest(t.Context())
			if err != nil {
				t.Fatal("start MITM test:", err)
			}
			// Exercise the virtual MITM destination with the initiating origin expected by apiserver.
			origin, err := api.NormalizeOrigin(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			virtualClient := &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					if address == net.JoinHostPort(target.String(), "443") {
						address = virtual.Listener.Addr().String()
					}
					return (&net.Dialer{}).DialContext(ctx, network, address)
				},
			}}
			defer virtualClient.CloseIdleConnections()
			proofRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, mitmTest.MITMURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			proofRequest.Header.Set("Origin", origin)
			proofResponse, err := virtualClient.Do(proofRequest)
			if err != nil {
				t.Fatal("virtual MITM destination:", err)
			}
			proofResponse.Body.Close()
			if proofResponse.StatusCode != http.StatusOK {
				t.Fatalf("virtual MITM proof status = %d", proofResponse.StatusCode)
			}
			if observed, err := c.MITMTest(t.Context(), mitmTest.ID); err != nil || !observed.MITMObserved || observed.CAFingerprint != authority.Fingerprint() {
				t.Fatal("MITM proof:", observed, err)
			}
		})
	}
}

type verificationDevices struct {
	DeviceStore
}

func (verificationDevices) DeviceState(netip.Addr, [6]byte) api.DeviceState {
	return api.DeviceState{MITM: &api.MITMState{Enabled: true}}
}
