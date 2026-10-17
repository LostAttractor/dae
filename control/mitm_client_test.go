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

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/clientmatch"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestMITMClientAPIControlsNewConnectionsAndSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := localca.Generate(cert, key, "client API", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := localca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	makePlane := func(selectors []string) *ControlPlane {
		t.Helper()
		extension := mitmRoutingPlugin("example.test")
		clients, err := clientmatch.Parse(selectors)
		if err != nil {
			t.Fatal(err)
		}
		plane := &ControlPlane{mitmHost: controlTestHost(t, extension, authority), settings: store, mitmClients: clients}
		if err := plane.restoreHTTPClients(); err != nil {
			t.Fatal(err)
		}
		return plane
	}
	plane := makePlane(nil)
	ip := netip.MustParseAddr("192.0.2.10")
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	other := [6]byte{2, 0, 0, 0, 0, 11}
	var resolveError error
	resolve := func(peer, _ netip.AddrPort) (apiserver.ClientIdentity, error) {
		source := peer.Addr()
		if source != ip {
			t.Fatalf("unexpected source: %s", source)
		}
		return apiserver.ClientIdentity{LinkType: "ethernet", MAC: mac}, resolveError
	}
	handler := plane.apiHandler("test", resolve, nil, nil)
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
		return plane.mitmMode("example.test", netip.AddrPortFrom(ip, 44300), netip.MustParseAddrPort("198.51.100.1:443"),
			&routingResult{Mac: sourceMAC}) != mitm.HTTPBypass
	}
	// The production resolver must reject every device endpoint when no LAN is
	// configured, even if the caller knows the CA fingerprint.
	handler = plane.APIHandler("test", nil, nil)
	request("GET", endpoint, "", 403)
	request("PUT", endpoint, `{"enabled":true}`, 403)
	request("DELETE", endpoint, "", 403)
	handler = plane.apiHandler("test", resolve, nil, nil)
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
	// A new plane restores the saved settings with its configured defaults.
	// Retired planes keep their own published policy, just like their routing predicates.
	reloaded := makePlane([]string{"all"})
	handler = reloaded.apiHandler("test", resolve, nil, nil)
	state = request("PUT", endpoint, `{"enabled":false}`, 200)
	if state.Enabled || state.Override == nil || *state.Override || selected(reloaded, mac) || !selected(reloaded, other) || !selected(plane, mac) {
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
