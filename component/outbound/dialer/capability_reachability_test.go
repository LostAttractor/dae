// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"bytes"
	"context"
	"errors"
	"github.com/daeuniverse/dae/component/outbound/internal/checktime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// A failure changes reachability, not capability. The failed representative
// stops serving; the recovery attempt proves another supported mode, which
// represents the path while the failed mode is probed again by health checks.
func TestFailureKeepsCapabilitiesAndRecoversThroughAnotherMode(t *testing.T) {
	for _, kind := range []checkKind{checkHealth, checkSelection} {
		t.Run(checkKindName[kind], func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
				{network: common.NetworkTCP6}, {network: common.NetworkTCP4},
				{network: common.NetworkUDP6, err: netproxy.UnsupportedTunnelTypeError},
				{network: common.NetworkUDP4, err: context.DeadlineExceeded},
			}})
			want := [common.NetworkTypeCount]networkState{
				common.NetworkTCP4: networkSupported, common.NetworkTCP6: networkSupported,
				common.NetworkUDP4: networkUnknown, common.NetworkUDP6: networkUnsupported,
			}
			group := d.group.observer.(*testGroup)
			before := group.changes.Load()
			applied, accepted := d.applyCheck(checkResult{kind: kind, generation: d.failures.generation,
				probes: []probeResult{{network: common.NetworkTCP6, err: errors.New("offline")}}})
			if !accepted || applied.success || group.changes.Load() != before+1 {
				t.Fatalf("failure was not published: %+v", applied)
			}
			if states := d.networkStates(); states != want {
				t.Fatalf("failure changed capabilities: %v", states)
			}
			for network := range common.NetworkIndex(common.NetworkTypeCount) {
				if d.Usable(network.NetworkType()) {
					t.Errorf("failed path still serves %v", network)
				}
			}
			var calls [common.NetworkTypeCount]atomic.Int32
			tcp6Offline := atomic.Bool{}
			tcp6Offline.Store(true)
			checker := newConnectivityChecker(d.pathRuntime, func(_ context.Context, network *common.NetworkType) error {
				calls[network.Index()].Add(1)
				if network.Index() == common.NetworkTCP6 && tcp6Offline.Load() {
					return context.DeadlineExceeded
				}
				return nil
			})
			defer checker.stopRetries()
			d.applyCheck(performCheck(checker, t.Context(), checkHealth))
			if got := d.representativeLocked(); got != common.NetworkTCP4 {
				t.Fatalf("representative = %v, want tcp4", got)
			}
			for network := range common.NetworkIndex(common.NetworkTypeCount) {
				wantCalls := int32(0)
				if want[network] == networkSupported {
					wantCalls = 1
				}
				if calls[network].Load() != wantCalls || d.Usable(network.NetworkType()) != (network == common.NetworkTCP4) {
					t.Errorf("%v recovery: calls=%d usable=%v", network, calls[network].Load(), d.Usable(network.NetworkType()))
				}
			}
			if states := d.networkStates(); states != want || !d.RuntimeStatus().Degraded {
				t.Fatalf("recovery changed capabilities or cleared degradation: %v", states)
			}
			result := performCheck(checker, t.Context(), checkHealth)
			if len(result.probes) != 2 || result.probes[0].network != common.NetworkTCP4 || result.probes[1].network != common.NetworkTCP6 {
				t.Fatalf("health did not probe the representative and the failing mode: %+v", result)
			}
			if applied, _ := d.applyCheck(result); !applied.success || d.Usable(common.NetworkTCP6.NetworkType()) {
				t.Fatalf("a still failing mode changed path health or served: %+v", applied)
			}
			tcp6Offline.Store(false)
			d.applyCheck(performCheck(checker, t.Context(), checkHealth))
			if got := d.representativeLocked(); got != common.NetworkTCP6 || !d.Usable(common.NetworkTCP6.NetworkType()) {
				t.Fatalf("recovered mode did not serve again: representative %v", got)
			}
		})
	}
}

// A failure leaves an unmonitored path with no recovery work: no group
// needs it back, so it neither retries nor sweeps capabilities.
func TestUnmonitoredFailureSchedulesNoRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		prepareRecoveryDialer(d)
		d.SetMonitoring(false)
		var calls atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
			calls.Add(1)
			return context.DeadlineExceeded
		})
		defer checker.stopRetries()
		checker.cancel = func() {}
		if !checker.finish(checkResult{kind: checkHealth,
			probes: []probeResult{{network: common.NetworkTCP4, err: context.DeadlineExceeded}}}) {
			t.Fatal("checker stopped")
		}
		checker.dispatch()
		time.Sleep(time.Hour)
		checker.dispatch()
		if d.RuntimeStatus().Healthy || checker.cancel != nil || calls.Load() != 0 || !checker.supportAt.IsZero() || !checker.healthAt.IsZero() {
			t.Fatal("an unmonitored failure scheduled recovery work")
		}
	})
}

// A group that starts monitoring a path that failed unmonitored resumes the
// path's recovery schedule; monitoring itself is no reason to probe at once.
func TestMonitoringFailedPathResumesRecoverySchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		prepareRecoveryDialer(d)
		d.SetMonitoring(false)
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
			return context.DeadlineExceeded
		})
		defer checker.stopRetries()
		checker.cancel = func() {}
		checker.finish(checkResult{kind: checkHealth,
			probes: []probeResult{{network: common.NetworkTCP4, err: context.DeadlineExceeded}}})
		checker.dispatch()
		if !checker.healthAt.IsZero() || !checker.supportAt.IsZero() {
			t.Fatal("unmonitored failure kept retrying")
		}
		time.Sleep(time.Minute)
		d.SetMonitoring(true)
		if d.connectivityCheckRequested() {
			t.Fatal("monitoring a failed path bypassed its recovery schedule")
		}
		checker.dispatch()
		low, high := checktime.Bounds(time.Minute/4, d.CheckIntervalMax)
		if delay := time.Until(checker.healthAt); checker.cancel != nil || delay < low || delay > high {
			t.Fatalf("monitoring resumed recovery in %v, want [%v, %v]", delay, low, high)
		}
		if snapshot := d.SelectionSnapshot(common.NetworkTCP4.NetworkType()); !snapshot.Recovering() {
			t.Fatalf("monitored failed path is not recovering by itself: %+v", snapshot)
		}
	})
}

// A retained caller keeps a failed path recovering on its downtime schedule.
// A supported mode that reports itself unsupported only fails: capability
// changes wait for a reload to relearn them.
func TestRetainedRecoveryFollowsDowntimeAndKeepsCapability(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newTestSessionTransport(netproxy.SessionConnected)
		d := newTestDialer(t, transport)
		prepareRecoveryDialer(d)
		d.SetMonitoring(false)
		release, err := d.Retain()
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		unsupported := false
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
			if unsupported {
				return netproxy.UnsupportedTunnelTypeError
			}
			return context.DeadlineExceeded
		})
		defer checker.stopRetries()
		checker.cancel = func() {}
		checker.finish(checkResult{kind: checkHealth, readiness: transport.Snapshot().ReadinessVersion,
			probes: []probeResult{{network: common.NetworkTCP4, err: context.DeadlineExceeded}}})
		checker.dispatch()
		for _, flip := range []bool{false, true} {
			// A seconds-old outage retries after the shortest recovery delay.
			low, high := checktime.Bounds(time.Second, d.CheckIntervalMax)
			if delay := time.Until(checker.healthAt); delay < low || delay > high || checker.cancel != nil {
				t.Fatalf("retained recovery bypassed backoff: delay=%v running=%v", delay, checker.cancel != nil)
			}
			time.Sleep(time.Until(checker.healthAt))
			unsupported = flip
			checker.dispatch()
			if checker.cancel == nil || checker.runningKind != checkHealth {
				t.Fatal("retained caller lost recovery")
			}
			checker.finish(<-checker.results)
			checker.dispatch()
		}
		if status := d.RuntimeStatus(); status.Healthy || checker.blockedBy != "" || status.SupportState[common.NetworkTCP4] != api.NetworkSupportConfirmed || checker.healthAt.IsZero() {
			t.Fatalf("an unsupported answer changed capability or stopped recovery: %+v", status)
		}
	})
}

// A failed path retries on one deadline whatever its modes: each attempt
// waits a quarter of the outage so far, and capability discovery is untouched.
func TestFailedPathRetriesFollowDowntime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		prepareRecoveryDialer(d)
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
			return context.DeadlineExceeded
		})
		defer checker.stopRetries()
		checker.cancel = func() {}
		checker.finish(checkResult{kind: checkHealth,
			probes: []probeResult{{network: common.NetworkTCP4, err: context.DeadlineExceeded}}})
		d.mu.Lock()
		d.failures.downSince = time.Now().Add(-time.Minute)
		since := d.failures.downSince
		d.mu.Unlock()
		round := checker.discoverySince
		time.Sleep(time.Until(checker.healthAt))
		for range 3 {
			checker.dispatch()
			if checker.cancel == nil || checker.runningKind != checkHealth {
				t.Fatal("recovery was not dispatched")
			}
			checker.finish(<-checker.results)
			low, high := checktime.Bounds(time.Since(since)/4, d.CheckIntervalMax)
			if delay := time.Until(checker.healthAt); delay < low || delay > high || !checker.supportAt.IsZero() {
				t.Fatalf("recovery delay=%v support=%v want [%v,%v]", delay, checker.supportAt, low, high)
			}
			checker.dispatch()
			if checker.cancel != nil {
				t.Fatal("failed recovery retried without waiting")
			}
			time.Sleep(time.Until(checker.healthAt))
		}
		if checker.discoverySince != round {
			t.Fatalf("recovery advanced the capability round: %v -> %v", round, checker.discoverySince)
		}
	})
}

func TestSelectionDiscoveryDoesNotLeaveAutomaticCheckDemand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		prepareRecoveryDialer(d)
		d.SetMonitoring(false)
		var calls atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
			calls.Add(1)
			return nil
		})
		defer checker.stopRetries()
		checker.cancel = func() {}
		checker.finish(checkResult{kind: checkHealth,
			probes: []probeResult{{network: common.NetworkTCP4, err: context.DeadlineExceeded}}})
		// Bounded selection checks can confirm every mode before the pending
		// background sweep. A manual check then resets the scheduled deadline.
		for _, network := range canonicalNetworkOrder {
			d.applyCheck(checkResult{kind: checkSelection, generation: d.failures.generation,
				probes: []probeResult{{network: network}}})
		}
		d.RequestManualCheck()
		checker.dispatch()
		checker.finish(<-checker.results)
		checker.dispatch()
		time.Sleep(2 * time.Hour)
		checker.dispatch()
		if checker.cancel != nil || calls.Load() != 1 || !checker.healthAt.IsZero() || !checker.supportAt.IsZero() {
			t.Fatal("completed discovery enabled periodic checks on a paused path")
		}
	})
}

// A reload relearns capabilities without taking a path out of service:
// supported modes keep serving until a probe settles them again, and modes
// found unsupported become discoverable. The representative is settled by
// its own health probe, so the sweep never changes the path's health.
func TestRelearnSettlesCapabilitiesWithoutLeavingService(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
		{network: common.NetworkTCP6}, {network: common.NetworkTCP4},
		{network: common.NetworkUDP6, err: netproxy.UnsupportedTunnelTypeError},
		{network: common.NetworkUDP4, err: context.DeadlineExceeded},
	}})
	group := d.group.observer.(*testGroup)
	d.RelearnCapabilities()
	if !d.Usable(common.NetworkTCP6.NetworkType()) || !d.Usable(common.NetworkTCP4.NetworkType()) {
		t.Fatal("relearning took supported modes out of service")
	}
	if state := d.networkStates()[common.NetworkUDP6]; state != networkUnknown {
		t.Fatalf("unsupported mode was not made discoverable: %v", state)
	}
	checker := newConnectivityChecker(d.pathRuntime, checkProbe([common.NetworkTypeCount]func(context.Context, *common.NetworkType) error{
		common.NetworkTCP6: func(context.Context, *common.NetworkType) error { return nil },
		common.NetworkTCP4: func(context.Context, *common.NetworkType) error { return netproxy.UnsupportedTunnelTypeError },
		common.NetworkUDP6: func(context.Context, *common.NetworkType) error { return nil },
		common.NetworkUDP4: func(context.Context, *common.NetworkType) error { return context.DeadlineExceeded },
	}))
	defer checker.stopRetries()
	if !checker.supportPending() {
		t.Fatal("relearning left no discovery work")
	}
	// The worker consumes the reload's request before sweeping.
	sweep := checker.performAttempt(t.Context(), d.beginConnectivityCheck(checkSupport))
	for _, probe := range sweep.probes {
		if probe.network == common.NetworkTCP6 {
			t.Fatal("the sweep probed the representative")
		}
	}
	d.applyCheck(sweep)
	want := [common.NetworkTypeCount]networkState{
		common.NetworkTCP4: networkUnsupported, common.NetworkTCP6: networkSupported,
		common.NetworkUDP4: networkUnknown, common.NetworkUDP6: networkSupported,
	}
	if states := d.networkStates(); states != want || !d.RuntimeStatus().Healthy || !d.Usable(common.NetworkUDP6.NetworkType()) {
		t.Fatalf("sweep did not settle the relearned modes: %v", states)
	}
	if force := SelectionForceMask(group.forceMask.Load()); !force.Contains(common.NetworkUDP6) {
		t.Fatalf("a newly supported mode did not refresh selection: %04b", force)
	}
	d.applyCheck(performCheck(checker, t.Context(), checkHealth))
	d.mu.RLock()
	relearn := d.health.relearn
	d.mu.RUnlock()
	if relearn != 0 {
		t.Fatalf("modes left to relearn after their probes: %04b", relearn)
	}
}

// A sweep that stops a relearned mode serving publishes it at once, whether
// the protocol rejects the mode or it stops answering: groups must not keep
// routing the mode to the path until its next health check.
func TestRelearnSweepPublishesModesThatStopServing(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput, previousLevel := logger.Out, logger.Level
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() { logger.SetOutput(previousOutput); logger.SetLevel(previousLevel) })
	for _, tc := range []struct {
		name string
		err  error
		log  string
	}{
		{"rejected", netproxy.UnsupportedTunnelTypeError, "Connectivity modes unsupported"},
		{"failing", context.DeadlineExceeded, "Connectivity mode lost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
				{network: common.NetworkTCP6}, {network: common.NetworkTCP4},
				{network: common.NetworkUDP6}, {network: common.NetworkUDP4},
			}})
			d.RelearnCapabilities()
			d.beginConnectivityCheck(checkSupport) // The worker consumes the reload's request.
			group := d.group.observer.(*testGroup)
			before := group.changes.Load()
			output.Reset()
			d.applyCheck(checkResult{kind: checkSupport, probes: []probeResult{
				{network: common.NetworkTCP4}, {network: common.NetworkUDP6},
				{network: common.NetworkUDP4, err: tc.err},
			}})
			if d.Usable(common.NetworkUDP4.NetworkType()) || !d.Usable(common.NetworkUDP6.NetworkType()) {
				t.Fatal("the sweep did not settle udp4 alone")
			}
			if group.changes.Load() == before {
				t.Fatal("groups were not told that udp4 stopped serving")
			}
			if logs := output.String(); !strings.Contains(logs, tc.log) || !strings.Contains(logs, "udp4") {
				t.Fatalf("udp4 stopping was not logged as %q:\n%s", tc.log, logs)
			}
		})
	}
}
