// SPDX-License-Identifier: AGPL-3.0-only

package mitmverify

import (
	"encoding/json/v2"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func testService(t *testing.T) *Service {
	t.Helper()
	targets, err := ParseTargets("", "")
	if err != nil {
		t.Fatal(err)
	}
	service, err := New("test-ca", targets, []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestMITMWitnessRequiresVirtualDestinationAndDeviceMAC(t *testing.T) {
	service := testService(t)
	ip, mac := netip.MustParseAddr("192.0.2.2"), [6]byte{2, 2}
	test, err := service.Start(ip, mac, netip.MustParseAddrPort("192.0.2.1:9080"), "http://192.0.2.1:9080", true)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", test.MITMURL, nil)
	r.Header.Set("Origin", "http://192.0.2.1:9080")
	r.RemoteAddr = "192.0.2.2:40000"
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
	var proof api.MITMTestProof
	if err := json.Unmarshal(data, &proof); err != nil || proof.ID != test.ID || proof.CAFingerprint != test.CAFingerprint {
		t.Fatalf("MITM proof: %s, %v", data, err)
	}
	if current, _ := service.Get(test.ID, ip, mac); !current.MITMObserved {
		t.Fatal("real plugin observation missing")
	}
	service.tests[test.ID].ExpiresAt = time.Now().Add(-time.Second)
	if _, ok := service.Get(test.ID, ip, mac); ok {
		t.Fatal("expired test retained")
	}
	replacement := testService(t)
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
		if _, err := New("", targets, []net.Addr{network}); err == nil {
			t.Fatalf("accepted target in %s", prefix)
		}
	}
}

func TestMITMChallengeBindsOriginDestinationAndGeneration(t *testing.T) {
	for _, origin := range []string{"http://192.0.2.1:9080", "https://192.0.2.1:9080"} {
		for _, invalid := range []string{"", "origin", "destination", "host", "plaintext", "disabled", "invalidated"} {
			t.Run(origin+"/"+invalid, func(t *testing.T) {
				service := testService(t)
				ip, mac := netip.MustParseAddr("192.0.2.2"), [6]byte{2, 2}
				test, err := service.Start(ip, mac, netip.MustParseAddrPort("192.0.2.1:9080"), origin, invalid != "disabled")
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("GET", test.MITMURL, nil)
				r.Header.Set("Origin", origin)
				flow := plugin.Flow{Host: DefaultIPv4, Port: 443, SourceMAC: mac, Destination: netip.MustParseAddrPort(DefaultIPv4 + ":443")}
				switch invalid {
				case "origin":
					r.Header.Set("Origin", "https://evil.example")
				case "destination":
					flow.Destination = netip.MustParseAddrPort("192.0.2.1:9080")
				case "host":
					r.Host = "192.0.2.1:9080"
				case "plaintext":
					r.URL.Scheme = "http"
				case "invalidated":
					service.Invalidate()
				}
				response, err := service.Wrap(flow, nil)(&plugin.Exchange{Request: r})
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				success := response.StatusCode == http.StatusOK
				if success != (invalid == "") {
					t.Fatalf("status=%d", response.StatusCode)
				}
				current, _ := service.Get(test.ID, ip, mac)
				if current.MITMObserved != success {
					t.Fatal("rejected request changed observation")
				}
			})
		}
	}
}

func TestMITMChallengeCapacityIsSharedAcrossDevices(t *testing.T) {
	service := testService(t)
	ip, mac := netip.MustParseAddr("192.0.2.2"), [6]byte{2, 2}
	local := netip.MustParseAddrPort("192.0.2.1:9080")
	const origin = "http://192.0.2.1:9080"
	var first api.MITMTest
	for range maxTests {
		test, err := service.Start(ip, mac, local, origin, true)
		if err != nil {
			break
		}
		first = test
	}
	if _, err := service.Start(ip.Next(), [6]byte{2, 3}, local, origin, true); err != nil {
		t.Fatalf("one device exhausted the shared challenge capacity: %v", err)
	}
	// Changing source IP must not let one verified device bypass its quota.
	if _, err := service.Start(ip.Next(), mac, local, origin, true); err == nil {
		t.Fatal("device bypassed its quota with another source IP")
	}
	if _, ok := service.Get(first.ID, ip, mac); !ok {
		t.Fatal("quota rejection invalidated an existing challenge")
	}
	service.tests[first.ID].ExpiresAt = time.Now().Add(-time.Second)
	if _, err := service.Start(ip, mac, local, origin, true); err != nil {
		t.Fatalf("expiry did not free the device's challenge slot: %v", err)
	}
}
