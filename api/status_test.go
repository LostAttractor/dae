// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStatusWireRoundTrip(t *testing.T) {
	want := benchmarkStatus()
	want.Groups[0].Nodes[0].InitialCheckDone = true
	want.Groups[0].Nodes[0].Availability.LastFailureDuration = time.Second
	want.Plugins = []PluginInstanceStatus{{ID: "example", Type: "example", State: "active",
		BufferMemory: &BufferMemoryStatus{Limit: 64 << 20, Used: 1 << 20, Peak: 2 << 20, Denied: 3}}}
	payload, err := json.Marshal(want, jsonv1.FormatDurationAsNano(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"last":30000000`, `"last_failure_duration":1000000000`, `"schema":8`, `"plugins":`} {
		if !strings.Contains(string(payload), field) {
			t.Fatalf("wire representation missing %s", field)
		}
	}
	var got StatusSnapshot
	if err := json.Unmarshal(payload, &got, jsonv1.FormatDurationAsNano(true)); err != nil {
		t.Fatal(err)
	}
	if got.Groups[0].Nodes[0].InitialCheckDone {
		t.Fatal("runtime-only initial check state leaked into API JSON")
	}
	encoded, err := json.Marshal(got, jsonv1.FormatDurationAsNano(true))
	if err != nil || string(encoded) != string(payload) {
		t.Fatal("status changed after round trip", err)
	}
	if !reflect.DeepEqual(got.Groups[0].Nodes[0].Latency, want.Groups[0].Nodes[0].Latency) {
		t.Fatal("latency units changed")
	}
	if !reflect.DeepEqual(got.Plugins, want.Plugins) {
		t.Fatal("MITM buffer memory statistics changed after round trip")
	}
}
