// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

type unreadBody struct{ t *testing.T }

func (b unreadBody) Read([]byte) (int, error) {
	b.t.Error("unauthorized request body was read")
	return 0, errors.New("body must not be read")
}
func (unreadBody) Close() error { return nil }

func TestAccessPolicyMustBeExplicit(t *testing.T) {
	for _, test := range []struct {
		name   string
		policy accessPolicy
	}{
		{"unspecified", 0},
		{"public-admin", accessPublic | accessAdmin},
		{"login-lan", accessLogin | accessLAN},
		{"multiple-scopes", accessLAN | accessDevice},
		{"unknown", 1 << 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("route accepted an unspecified or ambiguous access policy")
				}
			}()
			new(handler).route(http.NewServeMux(), "GET /test", test.policy, func(http.ResponseWriter, *http.Request, caller) {})
		})
	}
}

func TestAccessGatePrecedesBodyAndResourceAccess(t *testing.T) {
	// Nil stores deliberately make any premature resource access fail the test.
	for _, group := range []struct {
		name   string
		status int
		routes []string
	}{
		{"admin", 401, []string{
			"PUT /api/session", "GET /api/status", "GET /api/selectors",
			"PUT /api/selectors/unknown", "DELETE /api/selectors/unknown",
			"POST /api/probes", "POST /api/plugins/unknown/scripts/run",
			"POST /api/resources/refresh", "GET /api/resources", "POST /api/operations",
			"GET /api/operations/unknown", "POST /api/diagnostics/explain",
			"POST /api/clients/unknown/impact", "GET /api/clients", "GET /api/clients/unknown",
			"GET /api/devices/invalid", "PUT /api/clients/unknown/members/invalid",
			"DELETE /api/clients/unknown/members/invalid", "PUT /api/devices/invalid/mitm",
			"DELETE /api/devices/invalid/mitm",
		}},
		{"admin-self", 401, []string{
			"POST /api/device/diagnostics/explain", "POST /api/device/sets/known/impact",
			"POST /api/device/sets/unknown/impact",
		}},
		{"self", 403, []string{
			"GET /api/device", "GET /api/device/status", "GET /api/device/context",
			"PUT /api/device/sets/known",
			"PUT /api/device/sets/unknown", "DELETE /api/device/sets/known",
			"DELETE /api/device/sets/unknown", "PUT /api/device/mitm", "DELETE /api/device/mitm",
			"POST /api/device/certificate-tests", "GET /api/device/certificate-tests/unknown",
		}},
	} {
		for _, route := range group.routes {
			for _, credentials := range []string{"", "Bearer wrong", "Bearer secret"} {
				if group.name == "admin" && credentials == "Bearer secret" {
					continue
				}
				t.Run(route+"/"+credentials, func(t *testing.T) {
					method, path, _ := strings.Cut(route, " ")
					r := httptest.NewRequestWithContext(t.Context(), method, "http://192.0.2.1:9080"+path, nil)
					r.RemoteAddr = "192.0.2.10:45000"
					r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}))
					r.Header.Set("X-Dae-API", "1")
					r.Header.Set("Authorization", credentials)
					r.Body = unreadBody{t}
					w := httptest.NewRecorder()
					NewHandler(Options{APIKey: "secret", ResolveClient: rejectLANClient}).ServeHTTP(w, r)
					want := group.status
					if credentials == "Bearer wrong" {
						want = 401
					} else if group.name == "admin-self" && credentials == "Bearer secret" {
						want = 403 // Credentials do not supply the current device.
					}
					if w.Code != want {
						t.Fatalf("got %d: %s", w.Code, w.Body.String())
					}
					if want == 401 && w.Header().Get("WWW-Authenticate") != `Bearer realm="dae"` {
						t.Fatal("missing authentication challenge")
					}
					if strings.Contains(w.Body.String(), net.ErrClosed.Error()) {
						t.Fatal("response disclosed resolver internals")
					}
				})
			}
		}
	}
}

type gateDevices struct {
	DeviceStore
	queries int
	ip      netip.Addr
	mac     [6]byte
}

func (d *gateDevices) HasClientSet(name string) bool {
	d.queries++
	return name == "known"
}

func (d *gateDevices) UpdateClientSet(_ string, ip netip.Addr, mac [6]byte, _ bool) (api.DeviceState, error) {
	d.ip, d.mac = ip, mac
	return api.DeviceState{}, nil
}

type gateDiagnostics struct {
	DiagnosticStore
	context api.DiagnosticContext
}

func (d *gateDiagnostics) DiagnosticDeviceContext(input api.DiagnosticContext) api.DeviceContext {
	d.context = input
	return api.DeviceContext{}
}

func TestAccessGateResolvesPerRequestAndPassesIdentity(t *testing.T) {
	d := &gateDevices{}
	diagnostics := &gateDiagnostics{}
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	identity := ClientIdentity{LinkType: "ethernet", MAC: mac, IfIndex: 5, PhysicalIfIndex: 7}
	calls := 0
	h := NewHandler(Options{APIKey: "secret", Devices: d, Diagnostics: diagnostics,
		ResolveClient: func(netip.AddrPort, netip.AddrPort) (ClientIdentity, error) {
			calls++
			return identity, nil
		},
	})
	request := func(method, path string, want int) {
		t.Helper()
		before := calls
		headers := map[string]string{"X-Dae-API": "1"}
		if strings.HasSuffix(path, "/impact") {
			headers["Authorization"] = "Bearer secret"
		}
		w := sessionRequest(t, h, method, path, "", headers)
		if w.Code != want || calls != before+1 {
			t.Fatalf("%s: status=%d resolutions=%d body=%s", path, w.Code, calls-before, w.Body.String())
		}
	}
	request("PUT", "/api/device/sets/known", 200)
	if d.ip != netip.MustParseAddr("192.0.2.10") || d.mac != mac {
		t.Fatalf("store received wrong identity: %s %v", d.ip, d.mac)
	}
	request("PUT", "/api/device/sets/unknown", 404)
	if d.queries != 2 {
		t.Fatalf("expected resource checks only after authorization: %d", d.queries)
	}
	// The next request must use fresh evidence, even with the same source IP.
	identity = ClientIdentity{LinkType: "ip", IfIndex: 8, PhysicalIfIndex: 9}
	request("PUT", "/api/device/sets/known", 403)
	request("POST", "/api/device/sets/unknown/impact", 403)
	if d.queries != 2 {
		t.Fatal("MAC-less caller queried device resources")
	}
	request("GET", "/api/device/context", 200)
	if c := diagnostics.context; c.SourceIP != "192.0.2.10" || c.LinkType != "ip" || c.MAC != "" || *c.IfIndex != 8 || *c.PhysicalIfIndex != 9 {
		t.Fatalf("diagnostics did not inherit verified identity: %+v", c)
	}
}
