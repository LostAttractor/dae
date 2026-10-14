// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestCandidateStatsPublishLatestCheckAndSessionState(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "new identity"
		if retained {
			name = "retained identity"
		}
		t.Run(name, func(t *testing.T) {
			transport := newTestSessionTransport(netproxy.SessionConnected)
			d := newTestDialer(t, transport)
			identities := map[string]stats.NodeIdentity{d.StatsKey(): {Name: d.Name}}
			stats.DefaultStore.Reconcile(nil, nil)
			t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
			var oldChecks int64
			if retained {
				stats.DefaultStore.Reconcile(identities, nil)
				stats.DefaultStore.RecordNodeCheck(d.StatsKey(), false, time.Time{})
				oldChecks = 1
			}
			previous := stats.DefaultStore.GetNode(d.StatsKey())
			d.DeferStats()
			checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
				return nil
			})
			result := performCheck(checker, context.Background(), checkInitial)
			if applied, accepted := d.applyCheck(result); !accepted || !applied.success {
				t.Fatalf("candidate connectivity check = %+v, accepted=%v", applied, accepted)
			}
			if !d.RuntimeStatus().Healthy {
				t.Fatal("deferred statistics prevented candidate route selection")
			}
			d.reportDataPlaneFailure(netproxy.Failure{Cause: errors.New("candidate dial failed")})
			transport.state.Transition(netproxy.SessionDisconnected, errors.New("session lost before activation"))
			if !d.applySessionState(transport.Snapshot()) {
				t.Fatal("candidate session loss was not applied")
			}
			beforeCommit := stats.DefaultStore.GetNode(d.StatsKey())
			if beforeCommit.Seen != previous.Seen || beforeCommit.ChecksTotal != previous.ChecksTotal ||
				beforeCommit.LastCheckAt != previous.LastCheckAt || !beforeCommit.LastConnFailAt.IsZero() {
				t.Fatalf("candidate changed committed statistics: before=%+v after=%+v", previous, beforeCommit)
			}

			stats.DefaultStore.Reconcile(identities, nil)
			d.PublishStats()
			d.PublishStats()
			committed := stats.DefaultStore.GetNode(d.StatsKey())
			if !committed.Seen || committed.Alive || committed.ChecksTotal != oldChecks+1 ||
				committed.ChecksFailed != oldChecks || committed.LastCheckAt.IsZero() || committed.LastConnFailAt.IsZero() {
				t.Fatalf("activation lost or duplicated the check/session state: %+v", committed)
			}

			transport.state.Transition(netproxy.SessionConnected, nil)
			result = performCheck(checker, context.Background(), checkHealth)
			if applied, accepted := d.applyCheck(result); !accepted || !applied.success {
				t.Fatalf("activated connectivity check = %+v, accepted=%v", applied, accepted)
			}
			after := stats.DefaultStore.GetNode(d.StatsKey())
			if !after.Alive || after.ChecksTotal != oldChecks+2 {
				t.Fatalf("activated checks did not resume accounting: %+v", after)
			}
		})
	}
}

func TestUncheckedCandidateStatsWaitForPublication(t *testing.T) {
	d, _ := newLifetimeDialer(t)
	identities := map[string]stats.NodeIdentity{d.StatsKey(): {Name: d.Name}}
	stats.DefaultStore.Reconcile(identities, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	d.DeferStats()
	d.ActivateCheck(nil)
	if stats.DefaultStore.GetNode(d.StatsKey()).Seen {
		t.Fatal("unchecked candidate published before activation")
	}
	d.PublishStats()
	if got := stats.DefaultStore.GetNode(d.StatsKey()); !got.Seen || !got.Alive || got.ChecksTotal != 0 {
		t.Fatalf("unchecked candidate publication = %+v", got)
	}
}
