package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestAPIDeviceResolvesActualConnectionEndpoints(t *testing.T) {
	for _, test := range []struct{ remote, local string }{
		{"[::ffff:192.0.2.2]:12345", "192.0.2.1:9080"},
		{"[fe80::2%br-lan]:12345", "[fe80::1%br-lan]:9080"},
	} {
		t.Run(test.remote, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://192.0.2.99:9999/api/device", nil)
			r.RemoteAddr = test.remote
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(test.local))))
			w := httptest.NewRecorder()
			mac := [6]byte{2, 0, 0, 0, 0, 1}
			s := &Handler{options: Options{AllowLANAnonymous: true, ResolveClient: func(source, destination netip.AddrPort) (api.ClientIdentity, error) {
				wantSource := netip.MustParseAddrPort(test.remote)
				wantSource = netip.AddrPortFrom(wantSource.Addr().Unmap(), wantSource.Port())
				if source != wantSource || destination != netip.MustParseAddrPort(test.local) {
					t.Fatalf("resolved %v -> %v, want %v -> %v", source, destination, wantSource, test.local)
				}
				return api.ClientIdentity{LinkType: "ethernet", MAC: mac}, nil
			}}}
			who, ok := s.authorize(w, r, accessDevice)
			ip, gotMAC := who.ip, who.identity.MAC
			if !ok || gotMAC != mac || ip != netip.MustParseAddrPort(test.remote).Addr().Unmap() {
				t.Fatalf("device = %v / %v, ok = %v", ip, gotMAC, ok)
			}
		})
	}
}

func TestMITMOriginHandlesDefaultPortAndIPv6(t *testing.T) {
	for _, test := range []struct {
		host, origin, local string
		status              int
	}{
		{"192.0.2.1:80", "http://192.0.2.1", "192.0.2.1:80", 200},
		{"192.0.2.1", "http://192.0.2.1:80", "192.0.2.1:80", 200},
		{"192.0.2.1:80", "http://192.0.2.1:81", "192.0.2.1:80", 403},
		{"[2001:db8::1]:8081", "http://[2001:db8::1]:8081", "[2001:db8::1]:8081", 200},
	} {
		local, err := net.ResolveTCPAddr("tcp", test.local)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("GET", "http://"+test.host+"/api/device/mitm", nil)
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, local))
		request.Header.Set("Origin", test.origin)
		allowed := localIPHost(request) && sameOrigin(request)
		if allowed != (test.status == 200) {
			t.Errorf("host=%s origin=%s allowed=%v", test.host, test.origin, allowed)
		}
	}
}

func TestHTTPSOrigins(t *testing.T) {
	for _, test := range []struct {
		url, local, origin string
		same               bool
	}{
		{"https://192.0.2.1/api/certificate/tests/proof", "192.0.2.1:443", "https://192.0.2.1:443", true},
		{"https://192.0.2.1:443/api/certificate/tests/proof", "192.0.2.1:443", "https://192.0.2.1", true},
		{"https://192.0.2.1/api/certificate/tests/proof", "192.0.2.1:443", "http://192.0.2.1:443", false},
		{"https://192.0.2.1/api/certificate/tests/proof", "192.0.2.1:443", "http://192.0.2.1", false},
		{"https://192.0.2.1:80/api/certificate/tests/proof", "192.0.2.1:80", "http://192.0.2.1", false},
		{"https://[2001:db8::1]:9080/api/certificate/tests/proof", "[2001:db8::1]:9080", "https://[2001:db8::1]:9080", true},
		{"https://[2001:db8::1]:9080/api/certificate/tests/proof", "[2001:db8::1]:9080", "http://[2001:db8::1]:9080", false},
		{"https://192.0.2.1:9080/api/status", "192.0.2.1:9080", "http://192.0.2.1:9080", false},
		{"https://192.0.2.1:9080/api/certificate/tests/proof", "192.0.2.1:9080", "http://192.0.2.1:9081", false},
		{"https://192.0.2.1:9080/api/certificate/tests/proof", "192.0.2.1:9080", "http://evil.example:9080", false},
		{"http://192.0.2.1:9080/api/certificate/tests/proof", "192.0.2.1:9080", "https://192.0.2.1:9080", false},
	} {
		t.Run(test.url+"/"+test.origin, func(t *testing.T) {
			r := httptest.NewRequest("GET", test.url, nil)
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(test.local))))
			r.Header.Set("Origin", test.origin)
			if !localIPHost(r) {
				t.Fatal("literal listener address rejected")
			}
			if sameOrigin(r) != test.same {
				t.Fatal("incorrect same-origin decision")
			}

		})
	}
}
