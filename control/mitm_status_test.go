// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/api"
)

func TestStatusServerPluginsFollowPublishedPlane(t *testing.T) {
	server, err := api.StartStatusServer(filepath.Join(t.TempDir(), "status.sock"), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	firstPlugin := mitmRoutingPlugin("one.example")
	firstPlugin.details = map[string]string{"generation": "first"}
	first := &ControlPlane{mitmHost: controlTestHost(t, firstPlugin, nil)}
	secondPlugin := mitmRoutingPlugin("two.example", "three.example")
	secondPlugin.details = map[string]string{"generation": "second"}
	second := &ControlPlane{mitmHost: controlTestHost(t, secondPlugin, nil)}
	for _, test := range []struct {
		plane      *ControlPlane
		enabled    bool
		generation string
	}{
		{first, true, "first"},
		{nil, false, ""},
		{second, true, "second"},
		{&ControlPlane{}, false, ""},
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
		if (len(snapshot.MITMPlugins) > 0) != test.enabled {
			t.Fatalf("plugin status enabled=%v, want %v", len(snapshot.MITMPlugins) > 0, test.enabled)
		}
		if !test.enabled {
			continue
		}
		if len(snapshot.MITMPlugins) != 1 {
			t.Fatalf("unexpected plugins: %+v", snapshot.MITMPlugins)
		}
		status := snapshot.MITMPlugins[0]
		var details map[string]string
		if err := jsonv2.Unmarshal(status.Details, &details); err != nil {
			t.Fatal(err)
		}
		if status.ID != "test" || status.Type != "test" || status.State != "prepared" || status.Scopes != 1 || details["generation"] != test.generation {
			t.Fatalf("status retained another plane's plugin: %+v details=%v", status, details)
		}
	}
}
