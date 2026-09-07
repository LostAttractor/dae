// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	mitmca "github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestAPIPluginsFollowPublishedPlane(t *testing.T) {
	server := &apiserver.Server{}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(cert, key, "status API", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := mitmca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	firstPlugin := mitmRoutingPlugin("one.example")
	firstPlugin.details = map[string]string{"generation": "first"}
	first := &ControlPlane{mitmHost: controlTestHost(t, firstPlugin, authority)}
	secondPlugin := mitmRoutingPlugin("two.example", "three.example")
	secondPlugin.details = map[string]string{"generation": "second"}
	second := &ControlPlane{mitmHost: controlTestHost(t, secondPlugin, authority)}
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
			server.SetHandler(nil)
		} else {
			server.SetHandler(test.plane.APIHandler("test"))
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://unix/api/status", nil)
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "dae.sock", Net: "unix"}))
		server.ServeHTTP(response, request)
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
		if err := jsonv2.Unmarshal(response.Body.Bytes(), &snapshot, jsonv1.FormatDurationAsNano(true)); err != nil {
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
