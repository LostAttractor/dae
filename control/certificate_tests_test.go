// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/mitm/certtest"
)

func TestCertificateDiagnosticThroughProductionTCPAdmission(t *testing.T) {
	authority, roots := mitmQUICTestAuthority(t)
	for _, scenario := range []string{"trusted", "trusted IPv6 alternate source", "untrusted", "device disabled"} {
		t.Run(scenario, func(t *testing.T) {
			targets, err := certtest.ParseTargets("", "")
			if err != nil {
				t.Fatal(err)
			}
			service, err := certtest.New(authority, 9080, targets, []net.Addr{
				&net.IPNet{IP: net.ParseIP("192.0.2.20"), Mask: net.CIDRMask(24, 32)},
				&net.IPNet{IP: net.ParseIP("fd00::20"), Mask: net.CIDRMask(64, 128)},
			})
			if err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int32
			plane, _, param := newHTTPRequestRouteTestWithAuthority(t, "", service,
				func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("no diagnostic upstream")
				}, authority)
			plane.sniffingTimeout = time.Second
			plane.deviceRoutes = new(deviceRoutes)
			plane.soMarkFromDae = 37
			if err := plane.settings.SetMITM(param.routingResult.Mac, new(scenario != "device disabled")); err != nil {
				t.Fatal(err)
			}
			param.Dest = netip.AddrPortFrom(targets[0], 443)
			local, source := netip.MustParseAddrPort("192.0.2.20:9080"), param.Src.Addr()
			if scenario == "trusted IPv6 alternate source" {
				local, source = netip.MustParseAddrPort("[fd00::20]:9080"), netip.MustParseAddr("fd00::2")
				param.Dest = netip.AddrPortFrom(targets[1], 443)
				param.Src = netip.MustParseAddrPort("[2001:db8:1::2]:40000")
			}
			wantProof := scenario == "trusted" || scenario == "trusted IPv6 alternate source"
			test, err := service.Start(source, param.routingResult.Mac, local, scenario != "device disabled")
			if err != nil {
				t.Fatal(err)
			}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			served := make(chan error, 1)
			go func() {
				relay, err := plane.prepareTCPRelay(t.Context(), &mitmTupleConn{Conn: server, source: param.Src, destination: param.Dest}, param.routingResult)
				if relay != nil {
					err = relay.run()
				}
				served <- err
			}()
			trusted := roots
			if scenario == "untrusted" {
				trusted = x509.NewCertPool()
			}
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trusted}, DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
			defer transport.CloseIdleConnections()
			r, _ := http.NewRequestWithContext(t.Context(), "GET", test.MITMURL, nil)
			r.Header.Set("Origin", "http://"+local.String())
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(r)
			if wantProof {
				if err != nil {
					t.Fatal(err)
				}
				var proof api.CertificateTestProof
				decodeErr := json.UnmarshalRead(response.Body, &proof)
				response.Body.Close()
				if decodeErr != nil || response.StatusCode != 200 || proof.Stage != "mitm" || proof.ID != test.ID {
					t.Fatalf("invalid interception witness: %+v, %v", proof, decodeErr)
				}
				if !response.Close || response.ProtoMajor != 1 {
					t.Fatal("diagnostic allowed downstream connection reuse")
				}
			} else if err == nil {
				response.Body.Close()
				t.Fatal("disabled/untrusted device received a positive response")
			}
			client.Close()
			select {
			case <-served:
			case <-time.After(2 * time.Second):
				t.Fatal("diagnostic connection did not drain")
			}
			current, _ := service.Get(test.ID, source, param.routingResult.Mac)
			if current.MITMObserved != wantProof {
				t.Fatalf("false MITM verdict: %+v", current)
			}
			if scenario != "device disabled" && dials.Load() != 0 {
				t.Fatal("local diagnostic opened an upstream")
			}
		})
	}
}
