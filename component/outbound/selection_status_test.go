// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestSelectionStatusDoesNotWakeSleepingPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		primary, peer := new(failoverTransport), new(failoverTransport)
		primary.delay.Store(int64(time.Millisecond))
		peer.delay.Store(int64(20 * time.Millisecond))
		g := newFailoverTestGroup(t, testFailoverPolicy(), nil, true, primary, peer)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		before := peer.attempts.Load()
		for range 3 {
			active := g.NodeSelectionStatus(g.Dialers[0], g.Dialers[0].RuntimeStatus())
			runtime := g.Dialers[1].RuntimeStatus()
			sleeping := g.NodeSelectionStatus(g.Dialers[1], runtime)
			if active.Tracking != "selected" || sleeping.Tracking != "standby" || !runtime.Dormant || runtime.Healthy || !runtime.HasLatency || sleeping.MeasuredAt.IsZero() {
				t.Fatalf("selection status lost physical dormancy or historical samples: active=%+v sleeping=%+v runtime=%+v", active, sleeping, runtime)
			}
			time.Sleep(time.Second)
		}
		if peer.attempts.Load() != before {
			t.Fatal("reading selection status generated probe traffic")
		}
	})
}

func TestSharedMonitoringDoesNotMakeStandbyPhysicallyDormant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		primary, peer := new(failoverTransport), new(failoverTransport)
		primary.delay.Store(int64(time.Millisecond))
		peer.delay.Store(int64(20 * time.Millisecond))
		g := newFailoverTestGroup(t, testFailoverPolicy(), nil, true, primary, peer)
		d := g.Dialers[1]
		alias, ok := d.Share(d.Property, "shared-owner")
		if !ok {
			t.Fatal("could not share path")
		}
		owner := NewDialerGroup(alias.GlobalOption, "shared-owner", GroupKindSelector,
			[]*dialer.Dialer{alias}, emptyAnnotations(1), dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector}, nil)
		defer owner.Close()
		start := make(chan struct{})
		if _, err := owner.StartConnectivityChecks(start); err != nil {
			t.Fatal(err)
		}
		close(start)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		runtime := d.RuntimeStatus()
		if !runtime.Healthy || runtime.Dormant || runtime.CheckEnabled || g.NodeSelectionStatus(d, runtime).Tracking != "standby" {
			t.Fatalf("group-local standby hid shared monitoring: %+v", runtime)
		}
		peer.offline.Store(true)
		d.ReportDataPlaneError(errors.New("shared path failed"))
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		runtime = d.RuntimeStatus()
		if runtime.Healthy || runtime.Dormant || runtime.Recovery.RetryAt.IsZero() || g.NodeSelectionStatus(d, runtime).Tracking != "standby" {
			t.Fatalf("failed standby lost shared recovery state: %+v", runtime)
		}
	})
}
