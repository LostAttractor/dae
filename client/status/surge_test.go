// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestSurgeUsesInstanceReports(t *testing.T) {
	instances := []api.MITMInstanceStatus{
		{ID: "other", Type: "demo", Details: json.RawMessage(`{"tasks":1}`)},
		{ID: "first", Type: "surge", Details: json.RawMessage(`{"enabled":true,"modules":[{"name":"one","state":"loaded"}],"future_field":true}`)},
		{ID: "second", Type: "surge", Details: json.RawMessage(`{"enabled":true,"modules":[{"name":"two","state":"cached","warnings":["offline"]}]}`)},
	}
	report, err := Surge(instances)
	if err != nil || !report.Enabled || len(report.Modules) != 2 {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
	if report.Modules[0].Instance != "first" || report.Modules[1].Instance != "second" {
		t.Fatalf("instance identity lost: %+v", report.Modules)
	}
	output := RenderSurge(report, true)
	for _, want := range []string{"first", "second", "one", "two", "second/two: offline"} {
		if !strings.Contains(output, want) {
			t.Errorf("missing %q in %s", want, output)
		}
	}
	for _, raw := range []string{"", "null", "{"} {
		if _, err := Surge([]api.MITMInstanceStatus{{ID: "broken", Type: "surge", Details: json.RawMessage(raw)}}); err == nil {
			t.Errorf("invalid report %q accepted", raw)
		}
	}
}
