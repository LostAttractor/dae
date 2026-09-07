// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	jsonv2 "encoding/json/v2"
	"github.com/daeuniverse/dae/component/api"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestStatusServerSurgeFollowsPublishedPlane(t *testing.T) {
	server, err := api.StartStatusServer(filepath.Join(t.TempDir(), "status.sock"), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	first := &ControlPlane{mitmHost: controlTestHost(t, surgeRoutingEngine(t, "one.example"), nil)}
	second := &ControlPlane{mitmHost: controlTestHost(t, surgeRoutingEngine(t, "two.example", "three.example"), nil)}
	for _, test := range []struct {
		plane   *ControlPlane
		enabled bool
		hosts   int
	}{
		{first, true, 1},
		{nil, false, 0},
		{second, true, 2},
		{&ControlPlane{}, false, 0},
	} {
		if test.plane == nil {
			server.Publish(nil)
		} else {
			server.Publish(test.plane.StatusSnapshot)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		if test.plane == nil {
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("unpublished plane returned %d", response.Code)
			}
			continue
		}
		if response.Code != http.StatusOK {
			t.Fatalf("status: %d %s", response.Code, response.Body)
		}
		var snapshot api.StatusSnapshot
		if err := jsonv2.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.Surge.Enabled != test.enabled {
			t.Fatalf("Surge enabled = %v, want %v", snapshot.Surge.Enabled, test.enabled)
		}
		if test.enabled && (len(snapshot.Surge.Modules) != 1 || snapshot.Surge.Modules[0].Hostnames != test.hosts) {
			t.Fatalf("status retained another plane's modules: %+v", snapshot.Surge)
		}
	}
}
