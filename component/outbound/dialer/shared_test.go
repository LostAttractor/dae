// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
)

func shareTestDialer(t *testing.T, first *Dialer) *Dialer {
	t.Helper()
	member, ok := first.Share(first.Property, "second-group")
	if !ok {
		t.Fatal("could not share active runtime")
	}
	member.RegisterDialerGroup(new(testGroup), 0.25)
	t.Cleanup(func() { _ = member.Close() })
	return member
}

func TestSharedHealthAndGroupLocalLatency(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	other := shareTestDialer(t, d)
	// Keep the real worker behind its startup gate; apply deterministic results.
	other.ActivateCheck(make(chan struct{}))
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{
		d.StatsKey(): {Name: d.Name}, other.StatsKey(): {Name: other.Name},
	}, nil)
	initial := checkResult{kind: checkInitial, probes: []probeResult{
		{network: common.NetworkTCP4, latency: 100 * time.Millisecond},
		{network: common.NetworkTCP6, err: netproxy.UnsupportedTunnelTypeError},
		{network: common.NetworkUDP4, err: netproxy.UnsupportedTunnelTypeError},
		{network: common.NetworkUDP6, err: netproxy.UnsupportedTunnelTypeError},
	}}
	d.applyCheck(initial)
	d.applyCheck(checkResult{kind: checkHealth, probes: []probeResult{
		{network: common.NetworkTCP4, latency: 300 * time.Millisecond},
	}})
	a, b := d.RuntimeStatus(), other.RuntimeStatus()
	if !a.Healthy || !b.Healthy || a.Revision != b.Revision || a.Latency.MovingAvg != 200*time.Millisecond || b.Latency.MovingAvg != 150*time.Millisecond {
		t.Fatalf("shared health / local EMA: first=%+v second=%+v", a, b)
	}
	if a.Availability.ChecksTotal != 2 || b.Availability.ChecksTotal != 2 || d.StatsID() == other.StatsID() {
		t.Fatal("group-local statistics lost shared observations or identity")
	}
	d.applyCheck(checkResult{kind: checkHealth, probes: []probeResult{
		{network: common.NetworkTCP4, err: errors.New("offline")},
	}})
	a, b = d.RuntimeStatus(), other.RuntimeStatus()
	if a.Healthy || b.Healthy || a.Latency.Last != 300*time.Millisecond || b.Latency.Last != 300*time.Millisecond {
		t.Fatalf("failure polluted latency: first=%+v second=%+v", a, b)
	}
	for _, member := range []*Dialer{d, other} {
		if member.group.observer.(*testGroup).changes.Load() != 3 {
			t.Fatal("shared runtime did not notify each member's group")
		}
	}
	pathA := stats.DefaultStore.OpenConnection(d.StatsPath("first-group", common.NetworkTCP4.NetworkType()), false)
	defer pathA.Close()
	pathB := stats.DefaultStore.OpenConnection(other.StatsPath("second-group", common.NetworkTCP4.NetworkType()), false)
	defer pathB.Close()
	paths := stats.DefaultStore.SnapshotWithHistory()
	if paths[d.StatsPath("first-group", common.NetworkTCP4.NetworkType())].ActiveConnections != 1 ||
		paths[other.StatsPath("second-group", common.NetworkTCP4.NetworkType())].ActiveConnections != 1 {
		t.Fatal("traffic attribution crossed group boundaries")
	}
}

func TestSharedCheckDemandAndRecoverySurviveMemberClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newTestSessionTransport(netproxy.SessionDisconnected)
		d := newTestDialer(t, transport)
		other := shareTestDialer(t, d)
		d.SetCheckEnabled(false)
		other.SetCheckEnabled(false)
		var probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) (bool, error) {
			probes.Add(1)
			return true, nil
		})
		// Use the injected probe with the same shared activation/lifetime gate.
		d.checkActivated = true
		start := make(chan struct{})
		d.checkWG.Go(func() { checker.run(start) })
		d.ActivateCheck(start)
		other.ActivateCheck(start)
		close(start)
		defer d.Close()
		defer other.Close()
		synctest.Wait()
		time.Sleep(2 * time.Hour)
		if probes.Load() != 0 || transport.connects.Load() != 0 {
			t.Fatal("unselected members started a shared connection")
		}
		other.SetCheckEnabled(true)
		synctest.Wait()
		if probes.Load() != common.NetworkTypeCount || transport.connects.Load() != 1 {
			t.Fatalf("initial sweep was duplicated: probes=%d connects=%d", probes.Load(), transport.connects.Load())
		}
		if !d.RuntimeStatus().Healthy || d.RuntimeStatus().CheckEnabled || !other.RuntimeStatus().CheckEnabled {
			t.Fatal("member tracking and shared health were conflated")
		}
		d.SetCheckEnabled(true)
		other.SetCheckEnabled(false)
		synctest.Wait()
		if d.checkPaused {
			t.Fatal("one member canceled another member's check demand")
		}
		other.SetCheckEnabled(true)
		d.SetCheckEnabled(false)
		d.RequestManualCheck()
		other.RequestManualCheck()
		synctest.Wait()
		if probes.Load() != common.NetworkTypeCount+1 {
			t.Fatal("cross-group manual requests were not coalesced")
		}
		_ = d.Close()
		if other.ctx.Err() != nil {
			t.Fatal("closing the first group stopped the shared checker")
		}
		if d.Usable(common.NetworkTCP4.NetworkType()) || d.RuntimeStatus().Healthy || !other.RuntimeStatus().Healthy {
			t.Fatal("member retirement was conflated with shared health")
		}
		transport.state.Transition(netproxy.SessionDisconnected, errors.New("connection lost"))
		synctest.Wait()
		if !other.RuntimeStatus().Healthy || transport.connects.Load() != 2 {
			t.Fatal("remaining member did not recover the shared session")
		}
		other.SetCheckEnabled(false)
		synctest.Wait()
		count := probes.Load()
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if probes.Load() != count {
			t.Fatal("last deselection did not pause the worker")
		}
		other.RequestManualCheck()
		other.RequestManualCheck()
		synctest.Wait()
		if probes.Load() != count+1 || other.RuntimeStatus().CheckEnabled {
			t.Fatal("manual requests were not coalesced into one untracked check")
		}
	})
}

func TestSharedLateMemberWaitsForPreparation(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	prepareRecoveryDialer(d)
	d.recordLatencyLocked(25*time.Millisecond, true)
	d.checkedAt = time.Now()
	other := shareTestDialer(t, d)
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{other.StatsKey(): {Name: other.Name}}, nil)
	d.recordAvailability(true, true, time.Time{})
	d.notifyGroups(SelectionForceNone)
	if other.RuntimeStatus().Availability.Seen || other.group.observer.(*testGroup).changes.Load() != 0 {
		t.Fatal("unprepared member received statistics or callbacks")
	}
	other.DeferStats()
	other.ActivateCheck(make(chan struct{}))
	if status := other.RuntimeStatus(); !status.Healthy || !status.HasLatency || status.Latency.Last != 25*time.Millisecond || status.Availability.Seen {
		t.Fatalf("late member did not inherit health safely: %+v", status)
	}
	other.PublishStats()
	if availability := other.RuntimeStatus().Availability; !availability.Seen || !availability.Alive || availability.ChecksTotal != 0 {
		t.Fatalf("late member publication = %+v", availability)
	}
}

func TestSharedLifetimeWithRetainedCaller(t *testing.T) {
	d, transport := newLifetimeDialer(t)
	other := shareTestDialer(t, d)
	release, err := d.Retain()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_ = d.Close()
	if _, err := d.Retain(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed member accepted another retain")
	}
	_ = assertLifetimeDial(t, other).Close()
	_ = other.Close()
	if d.ctx.Err() == nil || transport.closed.Load() != 0 {
		t.Fatal("final member did not stop checks while preserving retained transport")
	}
	if _, ok := d.Share(d.Property, "late"); ok {
		t.Fatal("retired runtime was resurrected")
	}
	conn := assertLifetimeDial(t, d)
	release()
	_ = conn.Close()
	assertLifetimeRetired(t, d, transport)
}

func TestSharedConcurrentMemberClose(t *testing.T) {
	d, transport := newLifetimeDialer(t)
	members := []*Dialer{d}
	for range 16 {
		members = append(members, shareTestDialer(t, d))
	}
	var workers sync.WaitGroup
	for _, member := range members {
		workers.Go(func() { _ = member.Close() })
	}
	workers.Wait()
	assertLifetimeRetired(t, d, transport)
}
