// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/component/api"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/settings"
)

func TestMITMClientAPIControlsNewConnectionsAndSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(cert, key, "client API", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := mitmca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	makePlane := func(selectors []string) *ControlPlane {
		t.Helper()
		engine, err := surge.NewEngine(surge.EngineOptions{
			Modules:     []*surge.Module{{Name: "test", Hostnames: []string{"example.test"}}},
			Runtime:     &surge.Runtime{},
			MaxBodySize: 1024, MaxConcurrentScripts: 1, ScriptTimeout: time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		clients, err := clientmatch.Parse(selectors)
		if err != nil {
			t.Fatal(err)
		}
		return &ControlPlane{mitmHost: controlTestHost(t, engine, authority), settings: store, mitmClients: clients, routingMatcherBuilder: &RoutingMatcherBuilder{}}
	}
	plane := makePlane(nil)
	ip := netip.MustParseAddr("192.0.2.10")
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	other := [6]byte{2, 0, 0, 0, 0, 11}
	var resolveError error
	resolve := func(source netip.Addr) ([6]byte, error) {
		if source != ip {
			t.Fatalf("unexpected source: %s", source)
		}
		return mac, resolveError
	}
	handler := plane.apiHandler(resolve)
	endpoint := "http://192.0.2.1:8081/api/device/mitm"
	request := func(method, path, body string, code int) api.MITMState {
		t.Helper()
		w := httptest.NewRecorder()
		if method == http.MethodGet {
			path = strings.TrimSuffix(path, "/mitm")
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8081}))
		r.RemoteAddr = net.JoinHostPort(ip.String(), "45000")
		r.Header.Set("X-Dae-MITM", authority.Fingerprint())
		r.Header.Set("X-Dae-API", "1")
		// Forwarding headers cannot choose which device is changed.
		r.Header.Set("X-Forwarded-For", "192.0.2.11")
		r.Header.Set("Forwarded", "for=192.0.2.11")
		if method == http.MethodPut {
			r.Header.Set("Content-Type", "application/json")
		}
		handler.ServeHTTP(w, r)
		if w.Code != code {
			t.Fatalf("%s: status=%d, want=%d, body=%s", method, w.Code, code, w.Body.String())
		}
		var state api.DeviceState
		if code == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
				t.Fatal(err)
			}
		}
		if state.MITM == nil {
			return api.MITMState{}
		}
		return *state.MITM
	}
	selected := func(plane *ControlPlane, sourceMAC [6]byte) bool {
		return plane.shouldMITMClient("example.test", netip.AddrPortFrom(ip, 44300), netip.MustParseAddrPort("198.51.100.1:443"),
			&bpfRoutingResult{Mac: sourceMAC}, &DialOption{Outbound: &outbound.DialerGroup{Name: "direct"}})
	}
	// The production resolver must reject every device endpoint when no LAN is
	// configured, even if the caller knows the CA fingerprint.
	handler = plane.APIHandler()
	request("GET", endpoint, "", 403)
	request("PUT", endpoint, `{"enabled":true}`, 403)
	request("DELETE", endpoint, "", 403)
	handler = plane.apiHandler(resolve)
	if state := request("GET", endpoint, "", 200); state.Enabled || state.Override != nil {
		t.Fatalf("default state: %+v", state)
	}
	if selected(plane, mac) {
		t.Fatal("default client selected")
	}
	state := request("PUT", endpoint, `{"enabled":true}`, 200)
	if !state.Enabled || state.Override == nil || !selected(plane, mac) || selected(plane, other) {
		t.Fatalf("device enable did not remain MAC-scoped: %+v", state)
	}
	// A new plane shares live settings while changing configured defaults.
	reloaded := makePlane([]string{"all"})
	handler = reloaded.apiHandler(resolve)
	state = request("PUT", endpoint, `{"enabled":false}`, 200)
	if state.Enabled || state.Override == nil || *state.Override || selected(reloaded, mac) || !selected(reloaded, other) || selected(plane, mac) {
		t.Fatalf("device disable did not override all across reload: %+v", state)
	}
	state = request("DELETE", endpoint, "", 200)
	if !state.Enabled || state.Override != nil || !selected(reloaded, mac) {
		t.Fatalf("reset did not restore configuration: %+v", state)
	}
	resolveError = errors.New("no direct neighbor")
	request("PUT", endpoint, `{"enabled":false}`, 403)
	if !selected(reloaded, mac) {
		t.Fatal("unresolved peer changed device selection")
	}
}

func TestMITMDeviceAPIRejectsCrossOriginAndMalformedChanges(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(cert, key, "device API", time.Hour); err != nil {
		t.Fatal(err)
	}
	a, err := mitmca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := surge.NewEngine(surge.EngineOptions{
		Runtime:     &surge.Runtime{},
		MaxBodySize: 1024, MaxConcurrentScripts: 1, ScriptTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	plane := &ControlPlane{mitmHost: controlTestHost(t, engine, a), settings: store, routingMatcherBuilder: &RoutingMatcherBuilder{}}
	for _, test := range []struct {
		name, method, body, origin, site, contentType, marker, query, host string
		status                                                             int
	}{
		{name: "status", method: "GET", status: 200},
		{name: "foreign origin", method: "PUT", body: `{"enabled":true}`, contentType: "application/json", marker: a.Fingerprint(), origin: "http://evil.example", status: 403},
		{name: "foreign status", method: "GET", origin: "http://evil.example", status: 403},
		{name: "null origin", method: "GET", origin: "null", status: 403},
		{name: "foreign scheme", method: "GET", origin: "https://192.0.2.1:8081", status: 403},
		{name: "DNS rebinding", method: "GET", host: "evil.example:8081", origin: "http://evil.example:8081", status: 403},
		{name: "wrong local IP", method: "GET", host: "192.0.2.2:8081", status: 403},
		{name: "wrong local port", method: "GET", host: "192.0.2.1:9999", status: 403},
		{name: "cross-site metadata", method: "GET", site: "cross-site", status: 403},
		{name: "same-site metadata", method: "DELETE", marker: a.Fingerprint(), site: "same-site", status: 403},
		{name: "form mutation", method: "POST", body: "enabled=true", status: 405},
		{name: "preflight", method: "OPTIONS", status: 405},
		{name: "missing fingerprint", method: "DELETE", status: 403},
		{name: "stale fingerprint", method: "PUT", body: `{"enabled":true}`, contentType: "application/json", marker: "old CA", status: 409},
		{name: "text JSON", method: "PUT", body: `{"enabled":true}`, contentType: "text/plain", marker: a.Fingerprint(), status: 415},
		{name: "empty object", method: "PUT", body: `{}`, contentType: "application/json", marker: a.Fingerprint(), status: 400},
		{name: "null", method: "PUT", body: `{"enabled":null}`, contentType: "application/json", marker: a.Fingerprint(), status: 400},
		{name: "MAC injection", method: "PUT", body: `{"enabled":true,"mac":"00:11:22:33:44:55"}`, contentType: "application/json", marker: a.Fingerprint(), status: 400},
		{name: "duplicate property", method: "PUT", body: `{"enabled":false,"enabled":true}`, contentType: "application/json", marker: a.Fingerprint(), status: 400},
		{name: "trailing data", method: "PUT", body: `{"enabled":true}{}`, contentType: "application/json", marker: a.Fingerprint(), status: 400},
		{name: "oversize", method: "PUT", body: strings.Repeat(" ", 1025), contentType: "application/json", marker: a.Fingerprint(), status: 413},
		{name: "query injection", method: "GET", query: "?source=192.0.2.99", status: 400},
		{name: "GET body", method: "GET", body: `{"enabled":true}`, status: 400},
		{name: "DELETE body", method: "DELETE", marker: a.Fingerprint(), body: `{"mac":"00:11:22:33:44:55"}`, status: 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := plane.apiHandler(func(ip netip.Addr) ([6]byte, error) {
				called = true
				if ip != netip.MustParseAddr("192.0.2.10") {
					t.Fatalf("untrusted peer identity: %s", ip)
				}
				return [6]byte{2, 0, 0, 0, 0, 10}, nil
			})
			path := "http://192.0.2.1:8081/api/device"
			if test.method != http.MethodGet {
				path += "/mitm"
			}
			request := httptest.NewRequest(test.method, path+test.query, strings.NewReader(test.body))
			request.RemoteAddr = "[::ffff:192.0.2.10]:45000"
			request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8081}))
			if test.host != "" {
				request.Host = test.host
			}
			request.Header.Set("X-Dae-API", "1")
			for key, value := range map[string]string{"Origin": test.origin, "Sec-Fetch-Site": test.site, "Content-Type": test.contentType, "X-Dae-MITM": test.marker} {
				if value != "" {
					request.Header.Set(key, value)
				}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || called != (test.status == 200) {
				t.Fatalf("status=%d called=%v body=%s", response.Code, called, response.Body.String())
			}
			if response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("API allowed CORS or cached a device state")
			}
			if test.status != 200 && test.status != http.StatusMethodNotAllowed {
				var result struct{ Error string }
				if err := json.Unmarshal(response.Body.Bytes(), &result, json.MatchCaseInsensitiveNames(true)); err != nil || result.Error == "" {
					t.Fatalf("failure lacks a JSON error: %v, %s", err, response.Body.String())
				}
			}
		})
	}
}

func controlTestHost(t *testing.T, engine *surge.Engine, authority *mitmca.Authority) *mitm.Host {
	t.Helper()
	if authority == nil && len(engine.Plan().Scopes) > 0 {
		authority = &mitmca.Authority{}
	}
	host, err := mitm.New(mitm.Options{Authority: authority}, mitm.Instance{ID: "surge", Type: "surge", Plugin: engine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host
}
