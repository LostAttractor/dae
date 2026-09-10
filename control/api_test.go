// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	json "encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/api"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
)

func newAPITestPlane(t *testing.T, store *settings.Store) *ControlPlane {
	t.Helper()
	option := &dialer.GlobalOption{}
	var paths []*dialer.Dialer
	for _, name := range []string{"one", "two"} {
		runtime := netproxy.NewRuntime(netproxy.Layer{Data: downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })})
		paths = append(paths, dialer.NewDialer(runtime, option, &dialer.Property{Name: name, Link: "test://" + name}, true, "api-test"))
	}
	group := outbound.NewDialerGroup(option, "proxy", outbound.GroupKindSelector, paths, []*dialer.Annotation{{}, {}}, dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector}, nil)
	t.Cleanup(func() { _ = group.Close() })
	builder, matcher := buildClientMatcher(t, clientRule("gaming", false, "proxy"), clientRule("streaming", false, "proxy"))
	return &ControlPlane{outbounds: []*outbound.DialerGroup{group}, settings: store, apiToken: "test-secret", routingMatcherBuilder: builder, routingMatcher: matcher}
}
func apiTestRequest(handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://192.0.2.1:9080"+path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}))
	r.RemoteAddr = "192.0.2.10:45000"
	r.Header.Set("X-Dae-API", "1")
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}
func testClientMAC(netip.AddrPort, netip.AddrPort) ([6]byte, error) {
	return [6]byte{2, 0, 0, 0, 0, 10}, nil
}

func TestGlobalAPISelectorAndDeviceRulesWithoutMITM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	handler := plane.apiHandler(testClientMAC)
	group := plane.outbounds[0]
	selected := group.Dialers[1].StatsID()
	body := `{"node_id":"` + selected + `"}`
	// Global selectors remain available when no device-facing LAN is configured.
	production := plane.APIHandler()
	if w := apiTestRequest(production, "GET", "/api/selectors", "", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, method := range []string{"PUT", "DELETE"} {
		if w := apiTestRequest(production, method, "/api/device/sets/gaming", "", ""); w.Code != 403 || !strings.Contains(w.Body.String(), "global.lan_interface") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, test := range []struct {
		method, path, body, token string
		code                      int
	}{
		{"GET", "/api/selectors", "", "", 200},
		{"GET", "/api/device", "", "", 200},
		{"PUT", "/api/selectors/proxy", body, "", 401},
		{"PUT", "/api/selectors/proxy", body, "wrong", 401},
		{"PUT", "/api/selectors/missing", body, "test-secret", 404},
		{"PUT", "/api/selectors/proxy", `{"node_id":"missing"}`, "test-secret", 400},
		{"PUT", "/api/selectors/proxy", `{"node_id":"` + selected + `","mac":"02:00:00:00:00:11"}`, "test-secret", 400},
		{"PUT", "/api/device/sets/missing", "", "", 404},
		{"PUT", "/api/device/sets/gaming", `{"mac":"02:00:00:00:00:11"}`, "", 400},
		{"DELETE", "/api/device/mitm", "", "", 404},
	} {
		w := apiTestRequest(handler, test.method, test.path, test.body, test.token)
		if w.Code != test.code {
			t.Fatalf("%s %s = %d %s", test.method, test.path, w.Code, w.Body.String())
		}
	}
	if group.Selection() != group.DefaultSelection() || len(store.Members("gaming")) != 0 {
		t.Fatal("rejected requests changed settings")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("read/rejected API created state: %v", err)
	}
	for _, test := range []struct{ method, path, body, token string }{
		{"PUT", "/api/selectors/proxy", body, "test-secret"},
		{"PUT", "/api/device/sets/gaming", "", ""},
		{"PUT", "/api/device/sets/streaming", "", ""},
	} {
		if w := apiTestRequest(handler, test.method, test.path, test.body, test.token); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if group.Selection() != selected {
		t.Fatal("manual selection lost unavailable path")
	}
	mac, _ := testClientMAC(netip.AddrPort{}, netip.AddrPort{})
	requireClientRoute(t, plane.routingMatcher, mac, 443, consts.OutboundUserDefinedMin)
	requireClientRoute(t, plane.routingMatcher, [6]byte{2, 0, 0, 0, 0, 11}, 443, consts.OutboundDirect)
	reopened, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Selection("proxy") != selected || len(reopened.Members("gaming")) != 1 || len(reopened.Members("streaming")) != 1 {
		t.Fatal("API state did not survive reopening")
	}
	if w := apiTestRequest(handler, "DELETE", "/api/device/sets/gaming", "", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	requireClientRoute(t, plane.routingMatcher, mac, 443, consts.OutboundUserDefinedMin)
	if w := apiTestRequest(handler, "DELETE", "/api/device/sets/streaming", "", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	requireClientRoute(t, plane.routingMatcher, mac, 443, consts.OutboundDirect)
	if w := apiTestRequest(handler, "DELETE", "/api/selectors/proxy", "", "test-secret"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if group.Selection() != group.DefaultSelection() || store.Selection("proxy") != "" {
		t.Fatal("selector reset failed")
	}
	plane.apiToken = ""
	// Configuration changes publish a new handler, as on daemon reload.
	handler = plane.apiHandler(testClientMAC)
	if w := apiTestRequest(handler, "PUT", "/api/selectors/proxy", body, "test-secret"); w.Code != 403 {
		t.Fatal("selector mutation enabled without configured token")
	}
	// A disabled admin token must not disable device self-service.
	if w := apiTestRequest(handler, "PUT", "/api/device/sets/gaming", "", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}

func TestAPIWriteFailureRestoresRoutingAndSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	handler := plane.apiHandler(testClientMAC)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	group := plane.outbounds[0]
	for _, test := range []struct{ path, body, token string }{
		{"/api/selectors/proxy", `{"node_id":"` + group.Dialers[1].StatsID() + `"}`, "test-secret"},
		{"/api/device/sets/gaming", "", ""},
	} {
		if w := apiTestRequest(handler, "PUT", test.path, test.body, test.token); w.Code != 500 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	mac, _ := testClientMAC(netip.AddrPort{}, netip.AddrPort{})
	requireClientRoute(t, plane.routingMatcher, mac, 443, consts.OutboundDirect)
	if group.Selection() != group.DefaultSelection() || store.Selection("proxy") != "" || len(store.Members("gaming")) != 0 {
		t.Fatal("failed persistence changed effective state")
	}
}

func TestCandidateRestoresLatestRuntimeSettingsAtActivation(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	active := newAPITestPlane(t, store)
	candidate := newAPITestPlane(t, store)
	active.clients = map[string]config.Client{"gaming": {Description: "Game traffic"}}
	candidate.clients = map[string]config.Client{
		"gaming": {Description: "游戏 UDP 使用 <proxy>"},
		"unused": {Description: "Not referenced by routing"},
	}
	if err := candidate.restoreRuntimeSettings(false); err != nil {
		t.Fatal(err)
	}
	selected := active.outbounds[0].Dialers[1].StatsID()
	handler := active.apiHandler(testClientMAC)
	if w := apiTestRequest(handler, "PUT", "/api/selectors/proxy", `{"node_id":"`+selected+`"}`, "test-secret"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := apiTestRequest(handler, "PUT", "/api/device/sets/gaming", "", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if candidate.outbounds[0].Selection() == selected {
		t.Fatal("active API mutated an unpublished candidate")
	}
	// Activate performs this refresh after the old API's requests are drained.
	if err := candidate.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	if candidate.outbounds[0].Selection() != selected {
		t.Fatal("reload lost a choice made while loading")
	}
	mac, _ := testClientMAC(netip.AddrPort{}, netip.AddrPort{})
	requireClientRoute(t, candidate.routingMatcher, mac, 443, consts.OutboundUserDefinedMin)
	for _, plane := range []*ControlPlane{active, candidate} {
		w := apiTestRequest(plane.apiHandler(testClientMAC), "GET", "/api/device", "", "")
		var state api.DeviceState
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &state) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		want := []api.ClientSetState{
			{Name: "gaming", Description: plane.clients["gaming"].Description, Joined: true},
			{Name: "streaming"},
		}
		if !slices.Equal(state.Sets, want) {
			t.Fatalf("client metadata reload changed membership or exposed unused sets: got %+v, want %+v", state.Sets, want)
		}
	}
	if err := store.SetSelection("proxy", "removed-node"); err != nil {
		t.Fatal(err)
	}
	if err := candidate.restoreRuntimeSettings(false); err != nil {
		t.Fatal(err)
	}
	if store.Selection("proxy") != "removed-node" {
		t.Fatal("candidate erased active persisted choice")
	}
	if err := candidate.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	if store.Selection("proxy") != "" || candidate.outbounds[0].Selection() != candidate.outbounds[0].DefaultSelection() {
		t.Fatal("stale selection did not restore default")
	}
}

func TestDeviceAPIReportsIdentityFailureWithoutHidingSelectors(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	handler := plane.apiHandler(func(netip.AddrPort, netip.AddrPort) ([6]byte, error) { return [6]byte{}, net.ErrClosed })
	for _, path := range []string{"/api/device", "/api/device/sets/gaming"} {
		method := "GET"
		if path != "/api/device" {
			method = "PUT"
		}
		if w := apiTestRequest(handler, method, path, "", ""); w.Code != 403 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := apiTestRequest(handler, "GET", "/api/selectors", "", "")
	var state struct {
		Selectors    []api.SelectorState `json:"selectors"`
		AdminEnabled bool                `json:"admin_enabled"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &state) != nil || len(state.Selectors) != 1 || !state.AdminEnabled {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestGlobalAPIRequiresMutationHeader(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	handler := plane.apiHandler(testClientMAC)
	for _, path := range []string{"/api/device/sets/gaming", "/api/selectors/proxy"} {
		r := httptest.NewRequest("PUT", "http://192.0.2.1:9080"+path, nil)
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}))
		r.RemoteAddr = "192.0.2.10:45000"
		r.Header.Set("Authorization", "Bearer test-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if len(store.Members("gaming")) != 0 || store.Selection("proxy") != "" {
		t.Fatal("forbidden request changed saved state")
	}
}

func TestSelectorAPIUsesEscapedGroupName(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	plane.outbounds[0].Name = "proxy/香港"
	id := plane.outbounds[0].Dialers[1].StatsID()
	w := apiTestRequest(plane.apiHandler(testClientMAC), "PUT", "/api/selectors/proxy%2F%E9%A6%99%E6%B8%AF", `{"node_id":"`+id+`"}`, "test-secret")
	if w.Code != 200 || store.Selection("proxy/香港") != id {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestHostOnlyAPIDisablesCertificateAndMITM(t *testing.T) {
	plane := &ControlPlane{mitmHost: controlTestHost(t, &controlTestPlugin{}, nil), routingMatcherBuilder: &RoutingMatcherBuilder{}}
	handler := plane.apiHandler(testClientMAC)
	if w := apiTestRequest(handler, "GET", "/ca.cer", "", ""); w.Code != 404 {
		t.Fatalf("certificate without CA: %d", w.Code)
	}
	if state := plane.deviceState(netip.MustParseAddr("192.0.2.1"), [6]byte{}); state.MITM != nil {
		t.Fatalf("advertised MITM without a CA: %+v", state.MITM)
	}
	if w := apiTestRequest(handler, "PUT", "/api/device/mitm", "", ""); w.Code != 404 {
		t.Fatalf("MITM toggle without CA: %d", w.Code)
	}
}
