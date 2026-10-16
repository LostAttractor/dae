// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

type accessDiagnostics struct {
	DiagnosticStore
	calls     int
	context   api.DiagnosticContext
	inherited bool
}

func (d *accessDiagnostics) Explain(_ context.Context, request api.ExplainRequest, inherited bool) (*api.ExplainResponse, error) {
	d.calls++
	d.context, d.inherited = request.Context, inherited
	return &api.ExplainResponse{Current: api.ExplainResult{Notes: []string{"administrator-only"}}}, nil
}

func (d *accessDiagnostics) ClientImpact(_ context.Context, _ string, request api.ClientImpactRequest, inherited bool) (*api.ClientImpact, error) {
	d.calls++
	d.context, d.inherited = request.Context, inherited
	return &api.ClientImpact{Exports: []string{"administrator-only"}}, nil
}

func (d *accessDiagnostics) DiagnosticDeviceContext(input api.DiagnosticContext) api.DeviceContext {
	return api.DeviceContext{Context: input}
}

func TestDiagnosticAuthorizationMatrix(t *testing.T) {
	identity := ClientIdentity{LinkType: "ethernet", MAC: [6]byte{2, 0, 0, 0, 0, 10}, IfIndex: 5}
	verified := func(netip.AddrPort, netip.AddrPort) (ClientIdentity, error) { return identity, nil }
	login := sessionRequest(t, NewHandler(Options{APIKey: "secret"}), "PUT", "/api/session", "", map[string]string{"Authorization": "Bearer secret", "X-Dae-API": "1"})
	if login.Code != 204 {
		t.Fatal(login.Code, login.Body.String())
	}
	cookie := login.Result().Cookies()[0].String()
	for _, test := range []struct {
		name, key, bearer, cookie    string
		lan, ipOnly, unix            bool
		admin, self, device, context int
	}{
		{name: "keyed LAN", key: "secret", lan: true, admin: 401, self: 401, device: 401, context: 200},
		{name: "keyed IP LAN", key: "secret", lan: true, ipOnly: true, admin: 401, self: 401, device: 401, context: 200},
		{name: "keyed unknown ingress", key: "secret", admin: 401, self: 401, device: 401, context: 403},
		{name: "keyless LAN", lan: true, admin: 200, self: 200, device: 200, context: 200},
		{name: "keyless IP LAN", lan: true, ipOnly: true, admin: 200, self: 200, device: 403, context: 200},
		{name: "keyless unknown ingress", admin: 403, self: 403, device: 403, context: 403},
		{name: "keyless stale credentials", lan: true, bearer: "old", cookie: "dae_session=old", admin: 200, self: 200, device: 200, context: 200},
		{name: "key LAN", key: "secret", bearer: "secret", lan: true, admin: 200, self: 200, device: 200, context: 200},
		{name: "key IP LAN", key: "secret", bearer: "secret", lan: true, ipOnly: true, admin: 200, self: 200, device: 403, context: 200},
		{name: "key without LAN", key: "secret", bearer: "secret", admin: 200, self: 403, device: 403, context: 403},
		{name: "session LAN", key: "secret", cookie: cookie, lan: true, admin: 200, self: 200, device: 200, context: 200},
		{name: "session without LAN", key: "secret", cookie: cookie, admin: 200, self: 403, device: 403, context: 403},
		{name: "invalid key overrides session", key: "secret", bearer: "wrong", cookie: cookie, lan: true, admin: 401, self: 401, device: 401, context: 401},
		{name: "invalid session LAN", key: "secret", cookie: "dae_session=invalid", lan: true, admin: 401, self: 401, device: 401, context: 200},
		{name: "rotated session LAN", key: "new-secret", cookie: cookie, lan: true, admin: 401, self: 401, device: 401, context: 200},
		{name: "keyed local socket", key: "secret", unix: true, admin: 200, self: 403, device: 403, context: 403},
		{name: "keyless local socket", unix: true, admin: 200, self: 403, device: 403, context: 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &accessDiagnostics{}
			resolver := ClientResolver(rejectLANClient)
			if test.lan {
				resolver = verified
				if test.ipOnly {
					resolver = func(netip.AddrPort, netip.AddrPort) (ClientIdentity, error) {
						return ClientIdentity{LinkType: "ip", IfIndex: 5}, nil
					}
				}
			}
			h := NewHandler(Options{APIKey: test.key, ResolveClient: resolver, Diagnostics: store, Devices: &gateDevices{}})
			for _, route := range []struct {
				method, path, body string
				want               int
				self               bool
			}{
				{"POST", "/api/diagnostics/explain", `{}`, test.admin, false},
				{"POST", "/api/clients/known/impact", `{"joined":true}`, test.admin, false},
				{"POST", "/api/device/diagnostics/explain", `{}`, test.self, true},
				{"POST", "/api/device/sets/known/impact", `{"joined":true}`, test.device, true},
				{"GET", "/api/device/context", "", test.context, true},
			} {
				before := store.calls
				r := httptest.NewRequestWithContext(t.Context(), route.method, "http://192.0.2.1:9080"+route.path, strings.NewReader(route.body))
				r.RemoteAddr = "192.0.2.10:45000"
				var local net.Addr = &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}
				if test.unix {
					local = &net.UnixAddr{Name: "/run/dae/dae.sock", Net: "unix"}
				}
				r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
				r.Header.Set("X-Dae-API", "1")
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Cookie", test.cookie)
				if test.bearer != "" {
					r.Header.Set("Authorization", "Bearer "+test.bearer)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != route.want {
					t.Fatalf("%s: got %d, want %d: %s", route.path, w.Code, route.want, w.Body.String())
				}
				if route.want != 200 {
					if store.calls != before || strings.Contains(w.Body.String(), "administrator-only") {
						t.Fatalf("%s reached diagnostics without authorization", route.path)
					}
				} else if route.method == "POST" {
					if store.calls != before+1 || !strings.Contains(w.Body.String(), "administrator-only") {
						t.Fatalf("%s lost full administrator diagnostics", route.path)
					}
					if store.inherited != route.self {
						t.Fatalf("%s changed the identity scope", route.path)
					}
					if route.self && (store.context.SourceIP != "192.0.2.10" || store.context.IfIndex == nil || *store.context.IfIndex != 5) {
						t.Fatalf("%s lost verified identity: %+v", route.path, store.context)
					}
				}
			}
		})
	}
}

func TestLANCannotQueryAnyDiagnosticKind(t *testing.T) {
	store := &accessDiagnostics{}
	h := NewHandler(Options{APIKey: "secret", Diagnostics: store, ResolveClient: func(netip.AddrPort, netip.AddrPort) (ClientIdentity, error) {
		return ClientIdentity{LinkType: "ip", IfIndex: 5}, nil
	}})
	for _, kind := range []string{"flow", "dns", "domain", "outbound", "plugins"} {
		w := sessionRequest(t, h, "POST", "/api/device/diagnostics/explain", `{"kind":"`+kind+`","compare":{"bindings":[{"ip":"203.0.113.77","domains":["other-device.example"]}]}}`, map[string]string{"X-Dae-API": "1", "Content-Type": "application/json"})
		if w.Code != 401 || store.calls != 0 {
			t.Fatalf("kind %s: %d %s", kind, w.Code, w.Body.String())
		}
	}
}
