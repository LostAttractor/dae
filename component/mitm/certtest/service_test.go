// SPDX-License-Identifier: AGPL-3.0-only

package certtest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	mitmca "github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
)

func testAuthority(t *testing.T) (*mitmca.Authority, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(cert, key, t.Name(), time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := mitmca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := mitmca.ReadCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return authority, roots
}

func testService(t *testing.T, authority *mitmca.Authority, port uint16, addresses []net.Addr) *Service {
	t.Helper()
	targets, err := ParseTargets("", "")
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(authority, port, targets, addresses)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestBrowserChallengeRequiresTrustedTLSAndExactOrigin(t *testing.T) {
	authority, roots := testAuthority(t)
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port)
	service := testService(t, authority, port, []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}})
	endpoint := Endpoint{Service: service}
	server.Config.Handler = endpoint
	server.TLS = &tls.Config{GetConfigForClient: endpoint.TLSConfig}
	server.StartTLS()
	ip, mac := netip.MustParseAddr("127.0.0.1"), [6]byte{2, 1}
	test, err := service.Start(ip, mac, netip.AddrPortFrom(ip, port), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(t.Context(), "GET", test.TrustURL, nil)
	request.Header.Set("Origin", fmt.Sprintf("http://127.0.0.1:%d", port))
	if result, err := client.Do(request); err == nil {
		result.Body.Close()
		t.Fatal("untrusted CA completed a browser challenge")
	}
	if current, _ := service.Get(test.ID, ip, mac); current.TrustObserved {
		t.Fatal("failed TLS became a trust witness")
	}
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	request.Header.Set("Origin", "http://evil.example")
	result, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	result.Body.Close()
	if result.StatusCode != 403 || result.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("foreign origin accepted")
	}
	request.Header.Set("Origin", fmt.Sprintf("http://127.0.0.1:%d", port))
	result, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	var proof api.CertificateTestProof
	if err := json.UnmarshalRead(result.Body, &proof); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != 200 || proof.ID != test.ID || proof.Stage != "trust" || proof.CAFingerprint != authority.Fingerprint() {
		t.Fatalf("unexpected proof: %+v", proof)
	}
	if current, _ := service.Get(test.ID, ip, mac); !current.TrustObserved || current.MITMObserved {
		t.Fatalf("direct endpoint claimed MITM: %+v", current)
	}
}

func TestMITMWitnessRequiresVirtualDestinationAndDeviceMAC(t *testing.T) {
	authority, _ := testAuthority(t)
	addresses := []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)}}
	service := testService(t, authority, 9080, addresses)
	ip, mac := netip.MustParseAddr("192.0.2.2"), [6]byte{2, 2}
	test, err := service.Start(ip, mac, netip.MustParseAddrPort("192.0.2.1:9080"), true)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", test.MITMURL, nil)
	r.Header.Set("Origin", "http://192.0.2.1:9080")
	r.RemoteAddr = "192.0.2.2:40000"
	w := httptest.NewRecorder()
	Endpoint{Service: service}.ServeHTTP(w, r)
	current, _ := service.Get(test.ID, ip, mac)
	if w.Code == 200 || current.MITMObserved {
		t.Fatalf("direct endpoint claimed MITM: %+v", current)
	}
	if _, ok := service.Get(test.ID, ip, [6]byte{2, 3}); ok {
		t.Fatal("another MAC read the test")
	}
	flow := plugin.Flow{Host: DefaultIPv4, Port: 443, Source: netip.MustParseAddrPort("192.0.2.3:40000"), SourceMAC: [6]byte{2, 3}, Destination: netip.MustParseAddrPort(DefaultIPv4 + ":443")}
	result, err := service.Wrap(flow, nil)(&plugin.Exchange{Request: r})
	if err != nil {
		t.Fatal(err)
	}
	result.Body.Close()
	if result.StatusCode != 404 {
		t.Fatal("another source completed the challenge")
	}
	// A device can choose a different source IP when reaching an external target.
	flow.SourceMAC = mac
	result, err = service.Wrap(flow, nil)(&plugin.Exchange{Request: r})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	data, _ := io.ReadAll(result.Body)
	var proof api.CertificateTestProof
	if err := json.Unmarshal(data, &proof); err != nil || proof.Stage != "mitm" {
		t.Fatalf("MITM proof: %s, %v", data, err)
	}
	if current, _ := service.Get(test.ID, ip, mac); !current.MITMObserved {
		t.Fatal("real plugin observation missing")
	}
	service.tests[test.ID].ExpiresAt = time.Now().Add(-time.Second)
	if _, ok := service.Get(test.ID, ip, mac); ok {
		t.Fatal("expired test retained")
	}
	replacement := testService(t, authority, 9080, addresses)
	if replacement.Generation() == service.Generation() {
		t.Fatal("reload reused test generation")
	}
	if _, ok := replacement.Get(test.ID, ip, mac); ok {
		t.Fatal("replacement accepted stale proof")
	}
}

func TestVirtualTargetsRejectInvalidAddressesAndLocalSubnets(t *testing.T) {
	for _, pair := range [][2]string{{"127.0.0.1", ""}, {"224.0.0.1", ""}, {"", "fe80::1"}, {"", "::ffff:192.0.2.1"}, {"example.com", ""}, {"", "2001:db8::1%eth0"}} {
		if _, err := ParseTargets(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted %v", pair)
		}
	}
	targets, err := ParseTargets("192.0.2.254", "fd00::254")
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"192.0.2.1/24", "fd00::1/64"} {
		ip, network, _ := net.ParseCIDR(prefix)
		network.IP = ip
		if _, err := New(nil, 9080, targets, []net.Addr{network}); err == nil {
			t.Fatalf("accepted target in %s", prefix)
		}
	}
}
