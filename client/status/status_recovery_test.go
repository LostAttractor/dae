package status

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

func TestStatusRecoveryUsesActualDeadlineAndExecutor(t *testing.T) {
	withoutStatusColors(t)
	now := time.Unix(1800000000, 0)
	node := testNodeStatus(now)
	node.Healthy = false
	node.Recovery = api.RecoverySnapshot{
		Phase: api.RecoveryBackoff, Attempt: 2,
		RetryAt: now.Add(1700 * time.Millisecond),
	}
	group := api.GroupStatus{Nodes: []api.NodeStatus{node}}
	for _, verbose := range []bool{false, true} {
		_, rows := nodeTable(group, verbose, now)
		column := 2
		want := "fail (retry #3 in 1.7s)"
		if verbose {
			column = 14
			want = "retry #3 in 1.7s"
		}
		if got := rows[0][column]; got != want {
			t.Fatalf("recovery (verbose=%v) = %q", verbose, got)
		}
	}
	// The compact state keeps health visible while background work is pending.
	colorsEnabled = true
	for _, test := range []struct {
		healthy bool
		seen    bool
		action  string
		phase   api.RecoveryPhase
		want    string
		color   string
	}{
		{true, true, "replenish", api.RecoveryBackoff, "healthy (replenish capacity in 1.7s)", "\x1b[32m"},
		{true, true, "replenish", api.RecoveryConnecting, "healthy (replenishing capacity #2)", "\x1b[32m"},
		{true, true, "", api.RecoveryReady, "healthy", "\x1b[32m"},
		{true, true, "verify", api.RecoveryVerifying, "healthy", "\x1b[32m"},
		{false, true, "connect", api.RecoveryBackoff, "fail (retry #3 in 1.7s)", "\x1b[31m"},
		{false, false, "connect", api.RecoveryConnecting, "unknown (connecting #2)", "\x1b[33m"},
	} {
		status := node
		status.Healthy, status.Availability.Seen = test.healthy, test.seen
		status.Recovery.Action, status.Recovery.Phase = test.action, test.phase
		_, rows := nodeTable(api.GroupStatus{Nodes: []api.NodeStatus{status}}, false, now)
		got := rows[0][2].(string)
		if got != test.color+test.want+"\x1b[0m" {
			t.Errorf("compact state = %q, want %q in %q", got, test.want, test.color)
		}
	}
	colorsEnabled = false
	if got := formatRecovery(node.Recovery, now.Add(time.Minute)); got != "retry #3 in 0.0s" {
		t.Fatalf("elapsed deadline = %q", got)
	}
	node.Recovery.Action = "verify"
	if got := formatRecovery(node.Recovery, now); got != "recheck in 1.7s" {
		t.Fatalf("health verification shown as physical reconnect: %q", got)
	}
	node.Recovery = api.RecoverySnapshot{Phase: api.RecoveryConnecting, Executor: "library_managed"}
	if got := formatRecovery(node.Recovery, now); got != "protocol reconnecting (time unknown)" {
		t.Fatalf("library recovery = %q", got)
	}
	node.Recovery = api.RecoverySnapshot{Phase: api.RecoveryReady, Verification: "disabled"}
	if got := formatRecovery(node.Recovery, now); got != "ready (verification disabled)" {
		t.Fatalf("unchecked recovery = %q", got)
	}
	node.Recovery = api.RecoverySnapshot{Phase: api.RecoveryBlocked, Action: "replenish", BlockedBy: "auth"}
	if got := compactNodeState(node, now); got != "fail (blocked: auth; check configuration)" {
		t.Fatalf("blocked recovery = %q", got)
	}
	node.Recovery = api.RecoverySnapshot{Phase: api.RecoveryQueued, Action: "replenish", BlockedBy: "connectivity_slot"}
	if got := formatRecovery(node.Recovery, now); got != "queued for connection slot" {
		t.Fatalf("capacity queue = %q", got)
	}
}
