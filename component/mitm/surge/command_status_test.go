// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	jsonv1 "encoding/json"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/plugin"
)

func TestSurgeStatusWireAndTable(t *testing.T) {
	for _, status := range []Status{
		{},
		{Enabled: true},
		{Enabled: true, Modules: []ModuleStatus{
			{Name: "online", State: "loaded", Scripts: 2, Hostnames: 3},
			{Name: "offline", State: "cached", Error: "download failed", Warnings: []string{"refresh failed", "using cached module"}},
			{Name: "partial", State: "cached dependencies", Scripts: 1},
		}},
	} {
		details, err := jsonv1.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := surgeStatus([]plugin.InstanceStatus{{ID: "test", Type: "surge", Details: details}})
		if err != nil {
			t.Fatal(err)
		}
		output := renderSurgeStatus(decoded, true)
		if strings.Contains(output, "\x1b") {
			t.Fatalf("table contains terminal escapes: %q", output)
		}
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "|") || strings.HasPrefix(line, "+-") || strings.TrimRight(line, " \t") != line {
				t.Fatalf("table contains borders or trailing spaces: %q", line)
			}
		}
		if !status.Enabled && !strings.Contains(output, "disabled") {
			t.Fatalf("disabled status: %s", output)
		}
		if status.Enabled && len(status.Modules) == 0 && !strings.Contains(output, "no modules configured") {
			t.Fatalf("empty status: %s", output)
		}
		for _, module := range status.Modules {
			if !strings.Contains(output, module.Name) || !strings.Contains(output, module.State) {
				t.Fatalf("missing module %s (%s):\n%s", module.Name, module.State, output)
			}
		}
		if len(status.Modules) > 0 {
			for _, want := range []string{
				"Surge modules:\nINSTANCE",
				"\n\nErrors:\ntest/offline: download failed",
				"\n\nWarnings:\ntest/offline: refresh failed\ntest/offline: using cached module",
			} {
				if !strings.Contains(output, want) {
					t.Fatalf("missing %q in status:\n%s", want, output)
				}
			}
			startup := renderSurgeStatus(decoded, false)
			if strings.Contains(startup, "Warnings:") || strings.Contains(startup, "refresh failed") || !strings.Contains(startup, "\n\nErrors:\ntest/offline: download failed") {
				t.Fatalf("startup must retain errors without repeating warnings:\n%s", startup)
			}
			t.Log("\n" + output)
		}
	}
}

func TestSurgeStatusSelectsAndLabelsInstances(t *testing.T) {
	detail := jsonv1.RawMessage(`{"enabled":true,"modules":[{"name":"shared","state":"loaded","warnings":["unsupported rule"]}]}`)
	status, err := surgeStatus([]plugin.InstanceStatus{
		{ID: "native", Type: "example", Details: jsonv1.RawMessage(`{"pending":1}`)},
		{ID: "personal", Type: "surge", Details: detail},
		{ID: "work", Type: "surge", Details: detail},
	})
	if err != nil || len(status.Modules) != 2 || status.Modules[0].Instance != "personal" || status.Modules[1].Instance != "work" {
		t.Fatalf("mixed or mislabelled plugin reports: %+v, %v", status, err)
	}
	output := renderSurgeStatus(status, true)
	for _, name := range []string{"INSTANCE", "personal", "work", "\n\nWarnings:\npersonal/shared: unsupported rule\nwork/shared: unsupported rule"} {
		if !strings.Contains(output, name) {
			t.Fatalf("missing %q in table: %s", name, output)
		}
	}
	for _, detail := range []jsonv1.RawMessage{nil, jsonv1.RawMessage(`null`), jsonv1.RawMessage(`{"enabled":"bad"}`)} {
		if _, err := surgeStatus([]plugin.InstanceStatus{{ID: "broken", Type: "surge", Details: detail}}); err == nil {
			t.Fatal("invalid plugin report was silently accepted")
		}
	}
}
