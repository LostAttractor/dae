package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/api"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestStatusRecoveryUsesActualDeadlineAndExecutor(t *testing.T) {
	now := time.Unix(1800000000, 0)
	node := api.NodeStatus{Recovery: dialer.RecoverySnapshot{
		Phase: dialer.RecoveryBackoff, Attempt: 2, RetryTimeKnown: true,
		RetryAt: now.Add(1700 * time.Millisecond),
	}}
	group := api.GroupStatus{Nodes: []api.NodeStatus{node}}
	for _, verbose := range []bool{false, true} {
		_, rows := nodeTable(group, verbose, now)
		column := 2
		if verbose {
			column = 16
		}
		if got := rows[0][column]; got != "retry #3 in 1.7s" {
			t.Fatalf("recovery (verbose=%v) = %q", verbose, got)
		}
	}
	if got := formatRecovery(node.Recovery, now.Add(time.Minute)); got != "retry #3 in 0.0s" {
		t.Fatalf("elapsed deadline = %q", got)
	}
	node.Recovery.Action = "verify"
	if got := formatRecovery(node.Recovery, now); got != "recheck in 1.7s" {
		t.Fatalf("health verification shown as physical reconnect: %q", got)
	}
	node.Recovery = dialer.RecoverySnapshot{Phase: dialer.RecoveryConnecting, Executor: netproxy.RecoveryLibraryManaged}
	if got := formatRecovery(node.Recovery, now); got != "protocol reconnecting (time unknown)" {
		t.Fatalf("library recovery = %q", got)
	}
	node.Recovery = dialer.RecoverySnapshot{Phase: dialer.RecoveryReady, Verification: "disabled"}
	if got := formatRecovery(node.Recovery, now); got != "ready (verification disabled)" {
		t.Fatalf("unchecked recovery = %q", got)
	}
	node.Recovery = dialer.RecoverySnapshot{Phase: dialer.RecoveryBlocked, BlockedBy: "auth"}
	if got := formatRecovery(node.Recovery, now); !strings.Contains(got, "check configuration") {
		t.Fatalf("blocked recovery = %q", got)
	}
}

func TestStatusRecoveryRejectsInventedRetryTime(t *testing.T) {
	snapshot := validWireStatus()
	for _, recovery := range []dialer.RecoverySnapshot{
		{Phase: dialer.RecoveryBackoff, RetryTimeKnown: true},
		{Phase: dialer.RecoveryConnecting, RetryTimeKnown: true, RetryAt: time.Now()},
		{Phase: dialer.RecoveryBackoff, RetryAt: time.Now()},
	} {
		snapshot.Groups[0].Nodes[0].Recovery = recovery
		if err := validateStatus(&snapshot); err == nil {
			t.Fatalf("invalid recovery accepted: %+v", recovery)
		}
	}
}
