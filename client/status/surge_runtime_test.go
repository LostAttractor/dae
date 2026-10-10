// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestRuntimeMetricsInStatusViews(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	detail, err := json.Marshal(api.SurgeStatus{Enabled: true, Runtimes: []api.SurgeRuntimeStatus{{
		Instance: "untrusted", Backend: "nodejs", NodeJS: &api.NodeJSRuntimeStatus{
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
	for _, view := range []string{"status", "recent", "plugin", "surge"} {
		t.Run(view, func(t *testing.T) {
			var out strings.Builder
			switch view {
			case "status":
				Print(&out, snapshot, false)
			case "recent":
				PrintRecent(&out, snapshot)
			case "plugin":
				out.WriteString(RenderMITM(snapshot.Plugins, true))
			case "surge":
				out.WriteString(RenderSurge(report, false))
			}
			for _, want := range []string{"Surge runtime personal: nodejs", "active=1 idle=1 limit=4", "idle timeout=60s", "RSS=144.0 MiB PSS=96.0 MiB", "2/2 workers", "started=8 reused=27 start errors=2", "idle=5 failed/canceled=1"} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q in %s:\n%s", want, view, out.String())
				}
			}
			if strings.Contains(out.String(), "untrusted") {
				t.Fatal("runtime report overrode the plugin instance identity")
			}
			if view == "recent" {
				for line := range strings.SplitSeq(out.String(), "\n") {
					if text.StringWidthWithoutEscSequences(line) > 80 {
						t.Fatalf("runtime status overflows: %q", line)
					}
				}
			}
		})
	}
}

func TestRuntimeMemoryCoverage(t *testing.T) {
	n := &api.NodeJSRuntimeStatus{Active: 2, Limit: 4}
	runtimes := []api.SurgeRuntimeStatus{{Instance: "test", Backend: "nodejs", NodeJS: n}}
	if got := renderSurgeRuntimes(runtimes); !strings.Contains(got, "RSS/PSS unavailable") || !strings.Contains(got, "0/2 workers") {
		t.Fatalf("unsampled workers reported as zero memory: %s", got)
	}
	n.MemorySampledWorkers, n.RSSBytes, n.PSSBytes, n.MemorySampledAt = 1, 70<<20, 40<<20, time.Now()
	if got := renderSurgeRuntimes(runtimes); !strings.Contains(got, "1/2 workers") || !strings.Contains(got, "PSS=40.0 MiB") {
		t.Fatalf("partial memory sample lost coverage: %s", got)
	}
}
