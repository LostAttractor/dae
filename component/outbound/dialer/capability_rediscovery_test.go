// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"github.com/daeuniverse/dae/component/outbound/internal/checktime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestFailureInvalidatesEveryCapabilityBeforeRediscovery(t *testing.T) {
	for _, kind := range []checkKind{checkHealth, checkSelection} {
		t.Run(checkKindName[kind], func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
				{network: common.NetworkTCP6}, {network: common.NetworkTCP4},
				{network: common.NetworkUDP6, err: netproxy.UnsupportedTunnelTypeError},
				{network: common.NetworkUDP4, err: context.DeadlineExceeded},
			}})
			old := d.SelectionSnapshot(common.NetworkTCP4.NetworkType()).Proof
			group := d.group.observer.(*testGroup)
			before := group.changes.Load()
			applied, accepted := d.applyCheck(checkResult{kind: kind, generation: d.failures.generation,
				probes: []probeResult{{network: common.NetworkTCP6, err: errors.New("offline")}}})
			if !accepted || applied.success || !applied.rediscover || group.changes.Load() != before+1 {
				t.Fatalf("failure did not publish before rediscovery: %+v", applied)
			}
			for network, state := range d.networkStates() {
				if state != networkUnknown || d.Usable(common.NetworkIndex(network).NetworkType()) {
					t.Errorf("%v retained a capability: %v", common.NetworkIndex(network), state)
				}
			}
			var calls [common.NetworkTypeCount]atomic.Int32
			checker := newConnectivityChecker(d.pathRuntime, func(_ context.Context, network *common.NetworkType) error {
				calls[network.Index()].Add(1)
				if network.Index() == common.NetworkTCP6 {
					return context.DeadlineExceeded
				}
				return nil
			})
			defer checker.stopRetries()
			result := performCheck(checker, t.Context(), checkSupport)
			d.applyCheck(result)
			if got := firstSupportedNetwork(d.networkStates()); got != common.NetworkTCP4 {
				t.Fatalf("representative = %v, want tcp4", got)
			}
			for network := range common.NetworkIndex(common.NetworkTypeCount) {
				if calls[network].Load() != 1 || d.Usable(network.NetworkType()) != (network != common.NetworkTCP6) {
					t.Errorf("%v discovery: calls=%d usable=%v", network, calls[network].Load(), d.Usable(network.NetworkType()))
				}
			}
			if !d.RuntimeStatus().Degraded || d.ProofValid(old) {
				t.Fatal("rediscovery cleared degradation or revived the old proof")
			}
			if proof := d.SelectionSnapshot(common.NetworkUDP4.NetworkType()).Proof; !d.ProofValid(proof) {
				t.Fatal("newly confirmed modes did not share the new proof")
			}
			result = performCheck(checker, t.Context(), checkHealth)
			if len(result.probes) != 1 || result.probes[0].network != common.NetworkTCP4 || calls[common.NetworkTCP4].Load() != 2 {
				t.Fatalf("steady health did not use the new representative: %+v", result)
			}
		})
	}
}

func TestRediscoveryRunsOnceAfterMonitoringStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		prepareRecoveryDialer(d)
		d.SetMonitoring(false)
		var calls [common.NetworkTypeCount]atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(_ context.Context, network *common.NetworkType) error {
			calls[network.Index()].Add(1)
			return context.DeadlineExceeded
		})
		defer checker.stopRetries()
		checker.cancel = func() {}
		if !checker.finish(checkResult{kind: checkHealth,
			probes: []probeResult{{network: common.NetworkTCP4, err: context.DeadlineExceeded}}}) {
			t.Fatal("checker stopped")
		}
		if d.RuntimeStatus().Healthy || !checker.rediscover || !checker.healthAt.IsZero() {
			t.Fatal("failure did not schedule a separate discovery sweep")
		}
		checker.dispatch()
		if checker.runningKind != checkSupport || checker.cancel == nil {
			t.Fatal("paused monitoring suppressed the failure-triggered sweep")
		}
		checker.finish(<-checker.results)
		checker.dispatch()
		for network := range common.NetworkIndex(common.NetworkTypeCount) {
			if calls[network].Load() != 1 {
				t.Errorf("%v probes = %d", network, calls[network].Load())
			}
		}
		if checker.cancel != nil || checker.rediscover || !checker.supportAt.IsZero() || !checker.healthAt.IsZero() {
			t.Fatal("one sweep enabled ongoing checks without demand")
		}
	})
}

func TestRetainedRediscoveryPreservesBackoffAndStopsWhenUnsupported(t *testing.T) {
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
		for _, interval := range []time.Duration{time.Second, 4 * time.Second} {
			checker.dispatch()
			if checker.cancel == nil || checker.runningKind != checkSupport {
				t.Fatal("retained caller lost capability recovery")
			}
			checker.finish(<-checker.results)
			checker.dispatch()
			low, high := checktime.Bounds(interval, d.CheckIntervalMax)
			if delay := time.Until(checker.healthAt); delay < low || delay > high || checker.cancel != nil {
				t.Fatalf("retained recovery bypassed backoff: delay=%v running=%v", delay, checker.cancel != nil)
			}
			time.Sleep(time.Until(checker.healthAt))
		}
		unsupported = true
		checker.dispatch()
		checker.finish(<-checker.results)
		checker.dispatch()
		status := d.RuntimeStatus()
		if checker.cancel != nil || checker.blockedBy != "no_supported_network" || status.Recovery.Phase != api.RecoveryBlocked ||
			!checker.healthAt.IsZero() || !checker.supportAt.IsZero() {
			t.Fatalf("unsupported modes left an empty recovery loop: %+v", status)
		}
	})
}

func TestUnsuccessfulRediscoveryBacksOffWithoutResettingRound(t *testing.T) {
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
		for _, interval := range []time.Duration{time.Second, 4 * time.Second, 16 * time.Second} {
			checker.dispatch()
			if checker.cancel == nil || checker.runningKind != checkSupport {
				t.Fatal("rediscovery was not dispatched")
			}
			checker.finish(<-checker.results)
			low, high := checktime.Bounds(interval, d.CheckIntervalMax)
			if delay := time.Until(checker.supportAt); delay < low || delay > high || !checker.healthAt.IsZero() {
				t.Fatalf("support delay=%v health=%v want [%v,%v]", delay, checker.healthAt, low, high)
			}
			checker.dispatch()
			if checker.cancel != nil {
				t.Fatal("failed discovery retried without waiting")
			}
			time.Sleep(time.Until(checker.supportAt))
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
