// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestHandlerRoutesMatchOpenAPI(t *testing.T) {
	type parameter struct {
		Name, In string
		Required bool
	}
	type operation struct {
		Access     string                `json:"x-dae-access"`
		Connection string                `json:"x-dae-connection"`
		Bootstrap  bool                  `json:"x-dae-http-bootstrap"`
		Security   []map[string][]string `json:"security"`
		Parameters []parameter
	}
	type pathItem map[string]json.RawMessage
	read := func(file string) map[string]pathItem {
		t.Helper()
		data, err := os.ReadFile("../../docs/api/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct{ Paths map[string]pathItem }
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Paths
	}
	diagnostics := read("diagnostics.json")
	handler := NewHandler(Options{Certificates: &Certificates{}})
	// Stable monitoring operations; pprof.Index may additionally serve runtime-specific profiles.
	monitoring := map[string]accessPolicy{"GET /metrics": accessUser, "POST /debug/pprof/symbol": accessAdmin}
	for _, name := range []string{"", "profile", "heap", "allocs", "goroutine", "block", "mutex", "threadcreate", "trace", "cmdline", "symbol"} {
		monitoring["GET /debug/pprof/"+name] = accessAdmin
	}
	for path, item := range read("openapi.json") {
		if raw, ok := item["$ref"]; ok {
			var ref string
			if err := json.Unmarshal(raw, &ref); err != nil || ref != "./diagnostics.json#/paths/"+strings.ReplaceAll(path, "/", "~1") || diagnostics[path] == nil {
				t.Fatalf("invalid path reference for %s: %s", path, raw)
			}
			item = diagnostics[path]
			delete(diagnostics, path)
		}
		for method, raw := range item {
			if method == "parameters" {
				continue
			}
			route := strings.ToUpper(method) + " " + path
			policy, ok := handler.policies[route]
			if monitoringPath(path) {
				policy, ok = monitoring[route]
				delete(monitoring, route)
			}
			if !ok {
				t.Errorf("unregistered operation %s", route)
				continue
			}
			delete(handler.policies, route)
			var op operation
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatal(err)
			}
			access, connection := "user", ""
			switch {
			case policy&accessAdmin != 0:
				access = "admin"
			case policy&accessPublic != 0:
				access = "public"
				if policy&accessDirect != 0 {
					access = "challenge"
				}
			}
			switch {
			case policy&accessLAN != 0:
				connection = "lan"
			case policy&accessDevice != 0:
				connection = "device"
			case policy&accessDirect != 0:
				connection = "direct"
			}
			bootstrap := policy&accessBootstrap != 0 && access != "challenge"
			if op.Access != access || op.Connection != connection || op.Bootstrap != bootstrap {
				t.Errorf("%s: documented access %s/%s/bootstrap=%v, want %s/%s/bootstrap=%v", route, op.Access, op.Connection, op.Bootstrap, access, connection, bootstrap)
			}
			wantSecurity := []map[string][]string{{"bearerAuth": {}}, {"browserSession": {}}}
			switch {
			case policy&accessPublic != 0:
				wantSecurity = []map[string][]string{}
			case strings.HasPrefix(path, "/debug/pprof/"):
				wantSecurity = append(wantSecurity, map[string][]string{"pprofBasic": {}})
			case policy == accessLogin:
				wantSecurity = wantSecurity[:1]
			case policy&accessAdmin == 0:
				wantSecurity = append(wantSecurity, map[string][]string{})
			}
			if !reflect.DeepEqual(op.Security, wantSecurity) {
				t.Errorf("%s security = %v, want %v", route, op.Security, wantSecurity)
			}
			for header, required := range map[string]bool{"X-Dae-API": method != "get" && strings.HasPrefix(path, "/api/"), "X-Dae-MITM": method != "get" && strings.HasSuffix(path, "/mitm")} {
				if slices.ContainsFunc(op.Parameters, func(p parameter) bool { return p.Name == header && p.In == "header" && p.Required }) != required {
					t.Errorf("%s: required header %s should be %v", route, header, required)
				}
			}
		}
	}
	if len(handler.policies) != 0 {
		t.Fatalf("undocumented routes: %v", handler.policies)
	}

	if len(monitoring) != 0 {
		t.Errorf("undocumented monitoring operations: %v", monitoring)
	}
	if len(diagnostics) != 0 {
		t.Errorf("unreferenced diagnostic paths: %v", slices.Sorted(maps.Keys(diagnostics)))
	}

	local := newLocalHandler(LocalServices{})
	wantLocal := map[string]bool{
		"POST /api/operations":        true,
		"GET /api/operations/{id}":    true,
		"GET /api/resources":          true,
		"POST /api/resources/refresh": true,
	}
	gotLocal := make(map[string]bool, len(local.policies))
	for pattern := range local.policies {
		gotLocal[pattern] = true
	}
	if !maps.Equal(gotLocal, wantLocal) {
		t.Fatalf("local handler routes = %v, want %v", gotLocal, wantLocal)
	}
}
