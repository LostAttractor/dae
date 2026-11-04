// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"github.com/daeuniverse/dae/pkg/clitable"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/table"
)

func TestDormantStatusShowsOnlyHealthySleep(t *testing.T) {
	withoutStatusColors(t)
	now := time.Now()
	node := testNodeStatus(now)
	node.Healthy = false
	node.Health = api.NodeHealthHealthy
	node.Dormant = true
	node.SessionDetail.State = "disconnected"
	node.Selection = &api.SelectionStatus{Tracking: "standby", Priority: 7, Score: -time.Hour, MeasuredAt: now.Add(-time.Minute)}
	rendered := clitable.RenderLog(nil, []table.Row{compactNodeStatusRow(node, 0, api.NetworkValues[string]{}, false, now)})
	for _, want := range []string{"p=7*", "dormant", "10/20/30 @"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q in sleeping path status:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "[sleep]") || strings.Count(rendered, "dormant") != 1 {
		t.Fatalf("physical dormancy was duplicated:\n%s", rendered)
	}
	// A failed path shows its health and retry schedule even while it sleeps.
	node.Health = api.NodeHealthUnhealthy
	node.Selection.Degraded, node.Selection.RecoveryElapsed, node.Selection.FailureRecovery = true, 5*time.Second, 30*time.Second
	node.Recovery = api.RecoverySnapshot{Action: "verify", Phase: api.RecoveryBackoff, RetryAt: now.Add(10 * time.Second)}
	rendered = clitable.RenderLog(nil, []table.Row{compactNodeStatusRow(node, 0, api.NetworkValues[string]{}, false, now)})
	if !strings.Contains(rendered, "[degraded]") || strings.Contains(rendered, "dormant") || strings.Contains(rendered, "[recover") {
		t.Fatalf("failed sleeping path hid its failure:\n%s", rendered)
	}
	if got := compactNodeState(node, now); got != "unavailable (recheck in 10.0s)" {
		t.Fatalf("failed path hid its actual health and retry: %s", got)
	}
	if got := fmt.Sprint(nodeLatency(node)); got != "-" {
		t.Fatalf("unhealthy path displayed historical latency as current: %s", got)
	}
	node.Dormant = false
	// A dormant transport can be unavailable while its latest observation is healthy.
	node.Healthy = false
	node.Health = api.NodeHealthHealthy
	node.Recovery = api.RecoverySnapshot{Phase: api.RecoveryReady}
	if label := annotatedNodeLabel(node, 0); !strings.Contains(label, "[recover 5s/30s verified]") || strings.Contains(label, "[degraded]") {
		t.Fatalf("verified recovery did not display the observation window: %s", label)
	}
	if got := fmt.Sprint(nodeLatency(node)); got != "10/20/30" {
		t.Fatalf("recovery progress or selection score polluted real latency: %s", got)
	}
}
