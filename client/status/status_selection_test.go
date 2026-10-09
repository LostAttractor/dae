// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/table"
)

func TestDormantStatusPreservesMeasuredLatency(t *testing.T) {
	withoutStatusColors(t)
	now := time.Now()
	node := testNodeStatus(now)
	node.Healthy = false
	node.Dormant = true
	node.SessionDetail.State = "disconnected"
	node.Selection = &api.SelectionStatus{Tracking: "standby", Degraded: true,
		RecoveryElapsed: 5 * time.Second, FailureRecovery: 30 * time.Second,
		Priority: 7, Score: -time.Hour, MeasuredAt: now.Add(-time.Minute)}
	row := compactNodeStatusRow(node, 0, api.NetworkValues[string]{}, false, now)
	rendered := renderLogTable(nil, []table.Row{row})
	for _, want := range []string{"[degraded]", "p=7*", "dormant", "10/20/30 @"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q in sleeping path status:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "[sleep]") || strings.Contains(rendered, "[recover") || strings.Count(rendered, "dormant") != 1 {
		t.Fatalf("physical dormancy was duplicated or displayed as recovery observation:\n%s", rendered)
	}
	node.Dormant = false
	node.Recovery = api.RecoverySnapshot{Action: "verify", Phase: api.RecoveryBackoff, RetryAt: now.Add(10 * time.Second)}
	if got := compactNodeState(node, now); got != "fail (recheck in 10.0s)" {
		t.Fatalf("standby hid a shared worker's actual health and retry: %s", got)
	}
	if got := fmt.Sprint(nodeLatency(node)); got != "-" {
		t.Fatalf("unhealthy checking path displayed historical latency as current: %s", got)
	}
	node.Healthy = true
	node.Recovery = api.RecoverySnapshot{Phase: api.RecoveryReady}
	if label := annotatedNodeLabel(node, 0); !strings.Contains(label, "[recover 5s/30s verified]") || strings.Contains(label, "[degraded]") {
		t.Fatalf("verified recovery did not display the observation window: %s", label)
	}
	if got := fmt.Sprint(nodeLatency(node)); got != "10/20/30" {
		t.Fatalf("recovery progress or selection score polluted real latency: %s", got)
	}
}
