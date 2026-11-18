// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
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

func TestSharedRuntimeAccountsEachStatsKeyOnceDuringReload(t *testing.T) {
	old, _ := newLifetimeDialer(t)
	old.ActivateCheck(nil)
	share := func(scope string) *Dialer {
		d, ok := old.Share(old.Property, scope)
		if !ok {
			t.Fatal("could not share active path")
		}
		t.Cleanup(func() { _ = d.Close() })
		d.DeferStats()
		d.ActivateCheck(nil)
		return d
	}
	identities := map[string]stats.NodeIdentity{old.StatsKey(): {Name: old.Name}}
	stats.DefaultStore.Reconcile(identities, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	old.PublishStats()

	candidate := share("")
	otherGroup := share("other group")
	if stats.DefaultStore.GetNode(old.StatsKey()).Seen {
		t.Fatal("attaching a candidate published a new state for the existing key")
	}
	assertChecks := func(phase string, d *Dialer, total, failed int64) {
		t.Helper()
		got := stats.DefaultStore.GetNode(d.StatsKey())
		if got.ChecksTotal != total || got.ChecksFailed != failed ||
			got.Recent24h.ChecksTotal != total || got.Recent24h.ChecksFailed != failed {
			t.Fatalf("%s: availability for %q = %+v; want %d checks, %d failures", phase, d.StatsKey(), got, total, failed)
		}
	}

	old.recordAvailability(false, true, time.Time{})
	assertChecks("during preparation", old, 1, 1)
	assertChecks("unpublished group", otherGroup, 0, 0)

	identities[otherGroup.StatsKey()] = stats.NodeIdentity{Name: otherGroup.Name}
	stats.DefaultStore.Reconcile(identities, nil)
	candidate.PublishStats()
	otherGroup.PublishStats()
	assertChecks("at publication", candidate, 1, 1)
	assertChecks("new group at publication", otherGroup, 1, 1)

	old.recordAvailability(true, true, time.Time{})
	assertChecks("while both planes are live", candidate, 2, 1)
	assertChecks("independent group", otherGroup, 2, 1)

	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	candidate.recordAvailability(true, true, time.Time{})
	assertChecks("after the old plane retires", candidate, 3, 1)
}
