// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	surgeapi "github.com/daeuniverse/dae/component/mitm/surge/api"
)

func TestRuntimeMetricsInStatusViews(t *testing.T) {
	detail, err := json.Marshal(surgeapi.SurgeStatus{Enabled: true, Runtimes: []surgeapi.SurgeRuntimeStatus{{
		Instance: "untrusted", Backend: "nodejs", NodeJS: &surgeapi.NodeJSRuntimeStatus{
			Active: 1, Idle: 1, Limit: 4, Started: 8, Reused: 27, StartFailures: 2,
			IdleReaped: 5, Discarded: 1, RSSBytes: 144 << 20, PSSBytes: 96 << 20,
			MemorySampledWorkers: 2, MemorySampledAt: time.Now(), IdleTimeoutSeconds: 60,
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &api.StatusSnapshot{StartedAt: time.Now(), Plugins: []api.PluginInstanceStatus{{ID: "personal", Type: "surge", Details: detail}}}
	report, err := Surge(snapshot.Plugins)
	if err != nil {
		t.Fatal(err)
	}
	output := RenderSurge(report, false)
	for _, want := range []string{"Surge runtime personal: nodejs", "active=1 idle=1 limit=4", "idle timeout=60s", "RSS=144.0 MiB PSS=96.0 MiB", "2/2 workers", "started=8 reused=27 start errors=2", "idle=5 failed/canceled=1"} {
		if !strings.Contains(output, want) {
			t.Errorf("missing %q in plugin status:\n%s", want, output)
		}
	}
	if strings.Contains(output, "untrusted") {
		t.Fatal("runtime report overrode the plugin instance identity")
	}
}

func TestRuntimeMemoryCoverage(t *testing.T) {
	n := &surgeapi.NodeJSRuntimeStatus{Active: 2, Limit: 4}
	runtimes := []surgeapi.SurgeRuntimeStatus{{Instance: "test", Backend: "nodejs", NodeJS: n}}
	if got := renderSurgeRuntimes(runtimes); !strings.Contains(got, "RSS/PSS unavailable") || !strings.Contains(got, "0/2 workers") {
		t.Fatalf("unsampled workers reported as zero memory: %s", got)
	}
	n.MemorySampledWorkers, n.RSSBytes, n.PSSBytes, n.MemorySampledAt = 1, 70<<20, 40<<20, time.Now()
	if got := renderSurgeRuntimes(runtimes); !strings.Contains(got, "1/2 workers") || !strings.Contains(got, "PSS=40.0 MiB") {
		t.Fatalf("partial memory sample lost coverage: %s", got)
	}
}
