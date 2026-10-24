// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestStatusPluginDetailsRequireAdministration(t *testing.T) {
	snapshot := &api.StatusSnapshot{
		Schema: api.StatusSchemaVersion, Version: "test",
		BufferMemory: api.BufferMemoryStatus{Used: 123},
		Plugins:      []api.PluginInstanceStatus{{ID: "private", Type: "test", State: "active", Details: []byte(`{"output":"private script output"}`)}},
	}
	handler := NewHandler(Options{
		Status:  func() *api.StatusSnapshot { return snapshot },
		UserKey: "user", AdminKey: "admin", AllowLANAnonymous: true, ResolveClient: verifiedTestLAN,
	})
	for _, test := range []struct {
		name, key             string
		cookie, unix, details bool
	}{
		{name: "anonymous LAN"},
		{name: "user key", key: "user"},
		{name: "user cookie", key: "user", cookie: true},
		{name: "admin key", key: "admin", details: true},
		{name: "admin cookie", key: "admin", cookie: true, details: true},
		{name: "Unix", unix: true, details: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var data []byte
			if test.cookie {
				cookie := loginCookie(t, handler, test.key)
				response := sessionRequest(t, handler, "GET", "/api/status", "", map[string]string{
					"Cookie": cookie.Name + "=" + cookie.Value, "Sec-Fetch-Site": "same-origin",
				})
				if response.Code != 200 {
					t.Fatal(response.Code, response.Body)
				}
				data = response.Body.Bytes()
			} else {
				key := ""
				if test.key != "" {
					key = "Bearer " + test.key
				}
				response := accessRequest(t, handler, "GET", "/api/status", key, "", true, test.unix)
				if response.Code != 200 {
					t.Fatal(response.Code, response.Body)
				}
				data = response.Body.Bytes()
			}
			var got api.StatusSnapshot
			if err := json.Unmarshal(data, &got, jsonv1.FormatDurationAsNano(true)); err != nil {
				t.Fatal(err)
			}
			if got.Version != snapshot.Version || got.BufferMemory != snapshot.BufferMemory || len(got.Plugins) != 1 || got.Plugins[0].ID != "private" || got.Plugins[0].State != "active" {
				t.Fatalf("lost common status: %s", data)
			}
			if (len(got.Plugins[0].Details) != 0) != test.details {
				t.Fatalf("unexpected plugin details: %s", data)
			}
			if string(snapshot.Plugins[0].Details) != `{"output":"private script output"}` {
				t.Fatal("response filtering changed the shared snapshot")
			}
		})
	}
}
