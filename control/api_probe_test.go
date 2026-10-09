// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestProbeAPIAndSelectorWithoutDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlaneWithPolicy(t, store, dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector})
	handler := plane.apiHandler("test", testClientMAC, nil)
	group := plane.outbounds[0]
	first, second := group.Dialers[0].StatsID(), group.Dialers[1].StatsID()
	if node := plane.Selectors()[0].Nodes[1]; node.Checking || node.Tested || node.Tracking || !node.CheckedAt.IsZero() {
		t.Fatalf("dormant candidate = %+v", node)
	}
	state := plane.Selectors()[0]
	wire, err := json.Marshal(state)
	if err != nil || state.NodeID != first || strings.Contains(string(wire), "default_node_id") {
		t.Fatalf("implicit choice was exposed as a configured default: %s, %v", wire, err)
	}
	assertNodes := func(paths pathStatsIndex, count int) {
		t.Helper()
		status := newGroupStatus(paths, group, true)
		if len(status.Nodes) != count || status.Nodes[0].ID != first {
			t.Fatalf("status nodes = %+v", status.Nodes)
		}
	}
	assertNodes(pathStatsIndex{}, 1)
	assertNodes(pathStatsIndex{nodes: map[groupNodeKey]api.PathStats{
		{group: group.Name, nodeID: second}: {ActiveConnections: 1},
	}}, 2)
	assertNodes(pathStatsIndex{nodes: map[groupNodeKey]api.PathStats{
		{group: group.Name, nodeID: second}: {TotalConnections: 5},
	}}, 1)
	for _, test := range []struct {
		body, key string
		code      int
	}{
		{`{"outbound":"proxy"}`, "", 401},
		{`{"outbound":"proxy"}`, "wrong", 401},
		{`{"outbound":"missing"}`, "test-secret", 404},
		{`{"outbound":"proxy","node_id":"unknown"}`, "test-secret", 400},
		{`{"outbound":"proxy","url":"https://example.com"}`, "test-secret", 400},
		{`{"outbound":"proxy","node_id":12}`, "test-secret", 400},
		{`{}`, "test-secret", 400},
		{`null`, "test-secret", 400},
	} {
		w := apiTestRequest(handler, "POST", "/api/probes", test.body, test.key)
		if w.Code != test.code {
			t.Fatalf("probe %s = %d: %s", test.body, w.Code, w.Body.String())
		}
	}
	for _, test := range []struct{ method, path, body string }{
		{"POST", "/api/selectors/proxy/test", `{}`},
		{"PUT", "/api/selectors/proxy/tracking", `{"track_all":true}`},
	} {
		w := apiTestRequest(handler, test.method, test.path, test.body, "test-secret")
		if w.Code != 404 {
			t.Fatalf("removed operation %s returned %d", test.path, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/api/probes", nil)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "test.sock", Net: "unix"}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("probe without mutation header = %d", w.Code)
	}
	if group.Dialers[1].RuntimeStatus().Checking {
		t.Fatal("rejected requests queued work")
	}
	for _, id := range []string{second, ""} {
		body, _ := json.Marshal(api.ProbeRequest{Outbound: "proxy", NodeID: id})
		w := apiTestRequest(handler, "POST", "/api/probes", string(body), "test-secret")
		var accepted api.ProbeResponse
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &accepted) != nil {
			t.Fatalf("probe: %d %s", w.Code, w.Body.String())
		}
		want := []string{second}
		if id == "" {
			want = []string{first, second}
		}
		if accepted.Outbound != "proxy" || !slices.Equal(accepted.NodeIDs, want) {
			t.Fatalf("accepted = %+v", accepted)
		}
	}
	state = plane.Selectors()[0]
	if state.NodeID != first || state.TrackAll || !state.Nodes[1].Checking || state.Nodes[1].Tracking {
		t.Fatalf("probe changed selection/tracking: %+v", state)
	}
	assertNodes(pathStatsIndex{}, 2)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("probes wrote runtime settings")
	}
	w = apiTestRequest(handler, "PUT", "/api/selectors/proxy", `{"node_id":"`+second+`"}`, "test-secret")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = apiTestRequest(handler, "DELETE", "/api/selectors/proxy", "", "test-secret")
	if w.Code != 409 || group.Selection() != second || !group.Dialers[1].SelectionReference().Matches(store.Selection("proxy"), true) {
		t.Fatal("selector without default allowed a reset")
	}
	candidate := newAPITestPlaneWithPolicy(t, store, dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector})
	if err := candidate.restoreRuntimeSettings(false); err != nil {
		t.Fatal(err)
	}
	if state := candidate.Selectors()[0]; state.NodeID != second || state.DefaultNodeID != "" {
		t.Fatalf("restore = %+v", state)
	}
	explicit := newAPITestPlane(t, store) // Explicit selector(0).
	if err := explicit.restoreRuntimeSettings(false); err != nil {
		t.Fatal(err)
	}
	w = apiTestRequest(explicit.apiHandler("test", testClientMAC, nil), "DELETE", "/api/selectors/proxy", "", "test-secret")
	if w.Code != 200 || explicit.Selectors()[0].DefaultNodeID != first || explicit.outbounds[0].Selection() != first {
		t.Fatal("explicit default could not be restored")
	}
}

func TestProbeAPIUsesCheckedOutboundsBeyondSelectors(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlaneWithPolicy(t, store, dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random})
	option := &dialer.GlobalOption{}
	direct := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: statusTestDialer{}}), option, &dialer.Property{Name: "direct"}, false, "")
	builtin := outbound.NewDialerGroup(option, "direct", outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{direct}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = builtin.Close() })
	plane.outbounds = append(plane.outbounds, builtin)
	handler := plane.apiHandler("test", testClientMAC, nil)
	if w := apiTestRequest(handler, "POST", "/api/probes", `{"outbound":"proxy"}`, "test-secret"); w.Code != 202 {
		t.Fatalf("random probe = %d %s", w.Code, w.Body.String())
	}
	if w := apiTestRequest(handler, "POST", "/api/probes", `{"outbound":"direct"}`, "test-secret"); w.Code != 409 {
		t.Fatalf("unchecked probe = %d %s", w.Code, w.Body.String())
	}
}

func TestSelectorTrackingComesOnlyFromGroupConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	if err := os.WriteFile(path, []byte(`{"selectors":{},"clients":{},"mitm":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"", "track_all: true", "track_all: false"} {
		conf := outboundUsageConfig(t, `global {}
node { one: 'socks5://127.0.0.1:1'
       two: 'socks5://127.0.0.1:2' }
group { proxy { policy: selector check_async: true `+setting+` } }
routing { fallback: proxy }`)
		plane := outboundUsagePlane(t, conf, store, nil)
		state := plane.Selectors()[0]
		want := setting == "track_all: true"
		if state.TrackAll != want || state.Nodes[1].Tracking != want || state.DefaultNodeID != "" {
			t.Fatalf("%s: %+v", setting, state)
		}
		if err := plane.restoreRuntimeSettings(true); err != nil {
			t.Fatal(err)
		}
		if plane.Selectors()[0].TrackAll != want {
			t.Fatal("runtime restore changed config tracking")
		}
	}
}
