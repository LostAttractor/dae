package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
	"github.com/prometheus/client_golang/prometheus"
)

func prepareRecoveryDialer(d *Dialer) {
	d.mu.Lock()
	d.health = healthHealthy
	snapshot := d.sessionSnapshot()
	d.healthSeq = snapshot.ReadinessVersion
	for i := range d.networks {
		d.networks[i] = networkUnsupported
	}
	d.networks[common.NetworkTCP4] = networkSupported
	d.mu.Unlock()
}

func testRecoveryChecker(t *testing.T, d *Dialer) *connectivityChecker {
	t.Helper()
	c := newConnectivityChecker(d, func(context.Context, *common.NetworkType) (bool, error) { return true, nil })
	t.Cleanup(func() { c.stopRetries() })
	return c
}

// Model the run loop: apply the completed operation, then choose the next work.
func finishCheck(c *connectivityChecker, result checkResult) bool {
	if !c.finish(result) {
		return false
	}
	c.dispatch()
	return true
}

func waitRecoveryPhase(t *testing.T, d *Dialer, phase RecoveryPhase) RecoverySnapshot {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state := d.RuntimeStatus()
		if state.Recovery.Phase == phase {
			return state.Recovery
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("recovery did not become %s: %+v", phase, d.RuntimeStatus())
	return RecoverySnapshot{}
}

func TestReportDataPlaneErrorOnlyConfirmsUnknownUpstreamFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata netproxy.Failure
	}{
		{"stream", netproxy.Failure{Scope: netproxy.ScopeStream, Origin: netproxy.OriginPeer}},
		{"caller", netproxy.Failure{Scope: netproxy.ScopeUnknown, Origin: netproxy.OriginCaller}},
		{"target", netproxy.Failure{Scope: netproxy.ScopeUnknown, Origin: netproxy.OriginTarget}},
		{"cleanup", netproxy.Failure{Scope: netproxy.ScopeUnknown, Origin: netproxy.OriginLocalCleanup}},
		{"capacity", netproxy.Failure{Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonCapacity}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			prepareRecoveryDialer(d)
			d.ReportDataPlaneError(netproxy.WrapFailure(errors.New("failed"), tc.metadata))
			if status := d.RuntimeStatus(); !status.Healthy || status.ConfirmingFailure || d.connectivityCheckRequested() {
				t.Fatalf("isolated failure changed node health: %+v", status)
			}
		})
	}
	for _, reversed := range []bool{false, true} {
		t.Run(fmt.Sprintf("join_reversed_%v", reversed), func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			prepareRecoveryDialer(d)
			errs := []error{context.DeadlineExceeded, netproxy.WrapFailure(errors.New("unknown upstream failure"), netproxy.Failure{Origin: netproxy.OriginPeer})}
			if reversed {
				errs[0], errs[1] = errs[1], errs[0]
			}
			d.ReportDataPlaneError(errors.Join(errs...))
			if !d.RuntimeStatus().ConfirmingFailure || !d.connectivityCheckRequested() {
				t.Fatal("timeout hid independent unknown failure")
			}
		})
	}
}

func TestFatalTimeoutOwnerStateIsNotMaskedOrRetriedByOldRelays(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	resource := netproxy.ResourceRef{OwnerID: 1, ResourceID: 1, Generation: 1}
	failure := netproxy.WrapFailure(new(quic.IdleTimeoutError), netproxy.Failure{Resource: resource, Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerQUIC})
	transport.state.Publish(netproxy.StateEvent{State: netproxy.SessionDisconnected, Resource: resource, EpisodeID: 1, Cause: failure})
	event := transport.Snapshot()
	if !d.applySessionState(event) || d.RuntimeStatus().Healthy {
		t.Fatal("fatal QUIC timeout left node ready")
	}
	if d.applySessionState(event) {
		t.Fatal("duplicate owner event applied")
	}
	c := testRecoveryChecker(t, d)
	c.updateHealthSchedule(false)
	c.dispatch()
	want := d.RuntimeStatus().Recovery
	for i := 0; i < 50; i++ {
		d.ReportDataPlaneError(errors.Join(context.DeadlineExceeded, failure))
	}
	if got := d.RuntimeStatus().Recovery; got != want || d.connectivityCheckRequested() {
		t.Fatalf("relay cascade reset recovery: %+v -> %+v", want, got)
	}
	transport.state.Publish(netproxy.StateEvent{State: netproxy.SessionConnected, Resource: netproxy.ResourceRef{OwnerID: 1, ResourceID: 1, Generation: 2}, Accepting: true, UsableCapacity: 1})
	d.applySessionState(transport.Snapshot())
	prepareRecoveryDialer(d)
	d.ReportDataPlaneError(failure)
	if !d.RuntimeStatus().Healthy || d.RuntimeStatus().ConfirmingFailure {
		t.Fatal("old resource failure poisoned replacement")
	}
}

func TestRecoveryDeadlineMatchesTimer(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	c := testRecoveryChecker(t, d)
	c.healthInterval = 10 * time.Millisecond
	c.backingOff = true
	c.updateHealthSchedule(false)
	c.dispatch()
	snapshot := d.RuntimeStatus().Recovery
	if snapshot.Phase != RecoveryBackoff || snapshot.RetryAt.IsZero() {
		t.Fatalf("recovery = %+v", snapshot)
	}
	select {
	case fired := <-c.timer.C:
		if delta := fired.Sub(snapshot.RetryAt); delta < -time.Millisecond || delta > time.Millisecond {
			t.Fatalf("displayed deadline differs from timer by %s", delta)
		}
	case <-time.After(time.Second):
		t.Fatal("retry timer did not fire")
	}
}

func TestRecoveryQueuesBeforeConnecting(t *testing.T) {
	for i := 0; i < cap(connectivityCheckSlots); i++ {
		connectivityCheckSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(connectivityCheckSlots); i++ {
			<-connectivityCheckSlots
		}
	}()
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	d := newTestDialer(t, transport)
	c := testRecoveryChecker(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.connectFor(ctx, false); done <- err }()
	state := waitRecoveryPhase(t, d, RecoveryQueued)
	if state.Attempt != 0 || transport.connects.Load() != 0 {
		t.Fatal("waiting for a slot was counted as connecting")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("connect error = %v", err)
	}
}

func TestLibraryRecoveryDoesNotAddDaemonRetryLoop(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	transport.connectErr = netproxy.ErrNotConnected
	transport.state.Publish(netproxy.StateEvent{State: netproxy.SessionDisconnected, RecoveryExecutor: netproxy.RecoveryLibraryManaged})
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	c := testRecoveryChecker(t, d)
	c.start(checkHealth)
	result := <-c.results
	if !finishCheck(c, result) {
		t.Fatal("checker stopped")
	}
	state := d.RuntimeStatus().Recovery
	if state.Phase != RecoveryConnecting || !state.RetryAt.IsZero() || state.Executor != netproxy.RecoveryLibraryManaged {
		t.Fatalf("library recovery = %+v", state)
	}
	for i := 0; i < 10; i++ {
		c.handleSessionEvent(transport.Snapshot())

		c.dispatch()
		d.ReportDataPlaneError(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Scope: netproxy.ScopeSharedResource}))
	}
	if transport.connects.Load() != 1 || c.cancel != nil || d.connectivityCheckRequested() {
		t.Fatal("daemon added another library reconnect")
	}
	select {
	case <-c.timer.C:
		t.Fatal("daemon scheduled a library retry")
	default:
	}
	// The library dependency is ready; the next blocked layer belongs to DAE.
	// The chain as a whole remains unavailable until that layer reconnects.
	event := transport.Snapshot()
	event.RecoveryExecutor = netproxy.RecoveryDaemon
	event.ReadinessVersion++
	transport.state.Publish(event)
	transport.connectErr = nil
	c.handleSessionEvent(transport.Snapshot())
	c.dispatch()
	if c.cancel == nil {
		t.Fatal("library recovery suppressed the next layer's reconnect")
	}
	result = <-c.results
	c.handleSessionEvent(transport.Snapshot())
	if !finishCheck(c, result) || !d.RuntimeStatus().Healthy || transport.connects.Load() != 2 {
		t.Fatal("chain did not recover after library dependency became ready")
	}
}

func TestPermanentConnectFailureBlocksUntilEnvironmentRequest(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	transport.connectErr = netproxy.WrapFailure(errors.New("bad credentials"), netproxy.Failure{Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonAuth, Origin: netproxy.OriginPeer})
	d := newTestDialer(t, transport)
	c := testRecoveryChecker(t, d)
	c.start(checkInitial)
	if !finishCheck(c, <-c.results) {
		t.Fatal("checker stopped")
	}
	if state := d.RuntimeStatus().Recovery; state.Phase != RecoveryBlocked || state.BlockedBy != "auth" || !state.RetryAt.IsZero() {
		t.Fatalf("blocked recovery = %+v", state)
	}
	c.handleSessionEvent(transport.Snapshot())

	c.dispatch()
	if transport.connects.Load() != 1 {
		t.Fatal("blocked session retried without a trigger")
	}
	transport.connectErr = nil
	d.RequestConnectivityCheck()
	c.start(c.requestedCheckKind())
	if !finishCheck(c, <-c.results) {
		t.Fatal("checker stopped after environment request")
	}
	if c.blockedBy != "" || !d.RuntimeStatus().Healthy {
		t.Fatal("environment request did not recover")
	}
}

func TestReadinessDiagnosticDoesNotInvalidateHealthProof(t *testing.T) {
	for _, established := range []bool{false, true} {
		t.Run(fmt.Sprintf("established=%t", established), func(t *testing.T) {
			transport := newTestSessionTransport(netproxy.SessionConnected)
			if established {
				transport.state.Publish(netproxy.StateEvent{State: netproxy.SessionConnected, Accepting: true, UsableCapacity: 2, Resource: netproxy.ResourceRef{OwnerID: 1}})
			}
			d := newTestDialer(t, transport)
			prepareRecoveryDialer(d)
			before := transport.Snapshot()
			after := before
			after.UsableCapacity = 1
			transport.state.Publish(after)
			after = transport.Snapshot()
			if after.Seq == before.Seq || after.ReadinessVersion != before.ReadinessVersion {
				t.Fatal("test did not publish a diagnostic-only event")
			}
			d.applySessionState(after)
			_, applied := d.applyCheck(checkResult{kind: checkHealth, seq: before.Seq, readiness: before.ReadinessVersion, probes: []probeResult{{network: common.NetworkTCP4}}})
			if !applied || !d.RuntimeStatus().Healthy {
				t.Fatal("diagnostic-only event discarded valid health proof")
			}
		})
	}
}

func TestOwnerCleanupAndDependencyPhasesOverrideConnectionRequest(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	d := newTestDialer(t, transport)
	c := testRecoveryChecker(t, d)
	c.healthAt = time.Now().Add(time.Minute)
	c.dispatch()
	for _, phase := range []RecoveryPhase{RecoveryCleanup, RecoveryWaitingDependency} {
		event := transport.Snapshot()
		event.RecoveryPhase = string(phase)
		event.BlockedBy = "parent lease"
		transport.state.Publish(event)
		d.applySessionState(transport.Snapshot())
		state := d.RuntimeStatus().Recovery
		if state.Phase != phase || !state.RetryAt.IsZero() {
			t.Fatalf("owner phase was replaced by a guessed timer: %+v", state)
		}
	}
	event := transport.Snapshot()
	event.RecoveryPhase, event.BlockedBy = "queued", ""
	transport.state.Publish(event)
	d.applySessionState(transport.Snapshot())
	if state := d.RuntimeStatus().Recovery; state.Phase != RecoveryBackoff || state.RetryAt.IsZero() {
		t.Fatalf("actual daemon timer disappeared after cleanup: %+v", state)
	}
}

func TestHealthyPoolLossKeepsSiblingCapacityUsable(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	event := transport.Snapshot()
	event.UsableCapacity = 1
	event.RecoveryExecutor = netproxy.RecoveryDaemon
	event.Cause = netproxy.WrapFailure(errors.New("one pool slot reset"), netproxy.Failure{Scope: netproxy.ScopeSharedResource,
		Resource: netproxy.ResourceRef{OwnerID: 1, ResourceID: 9, Generation: 1}, Reason: netproxy.ReasonReset})
	transport.state.Publish(event)
	if d.applySessionState(transport.Snapshot()) {
		t.Fatal("pool diagnostic requested a node reconnect")
	}
	if status := d.RuntimeStatus(); !status.Healthy || status.ConfirmingFailure {
		t.Fatalf("sibling capacity became unusable: %+v", status)
	}
	if d.connectivityCheckRequested() {
		t.Fatal("pool diagnostic requested a health confirmation")
	}
	if d.RuntimeStatus().Failure == nil {
		t.Fatal("pool capacity loss was not reported")
	}
	d.checksConnectivity = false
	event = transport.Snapshot()
	event.RecoveryPhase = "ready"
	transport.state.Publish(event)
	d.applySessionState(transport.Snapshot())
	if status := d.RuntimeStatus(); !status.Healthy || status.Failure == nil {
		t.Fatalf("unchecked diagnostic erased a still degraded pool: %+v", status)
	}
}

func TestInterleavedResourceEpisodesPreserveCurrentFailureAndBackoff(t *testing.T) {
	for _, separatePublishers := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate_publishers=%t", separatePublishers), func(t *testing.T) {
			transport := &testCapacityTransport{newTestSessionTransport(netproxy.SessionConnected)}
			event := transport.Snapshot()
			event.PublisherID = 100
			event.RecoveryExecutor = netproxy.RecoveryDaemon
			transport.state.Publish(event)
			d := newTestDialer(t, transport)
			prepareRecoveryDialer(d)
			stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{d.StatsKey(): {Name: d.Name}}, nil)
			t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
			stats.DefaultStore.RecordNodeState(d.StatsKey(), true, time.Time{})
			registry := prometheus.NewRegistry()
			registry.MustRegister(stats.DefaultStore)
			failures := func() float64 {
				t.Helper()
				families, err := registry.Gather()
				if err != nil {
					t.Fatal(err)
				}
				for _, family := range families {
					if family.GetName() != "dae_resource_failures_total" {
						continue
					}
					for _, metric := range family.Metric {
						for _, label := range metric.Label {
							if label.GetName() == "id" && label.GetValue() == d.StatsID() {
								return metric.GetCounter().GetValue()
							}
						}
					}
				}
				return 0
			}
			transport.connectErr = errors.New("replacement dial failed")
			c := testRecoveryChecker(t, d)
			publish := func(publisher, episode uint64, cause string) {
				event := transport.Snapshot()
				event.PublisherID, event.EpisodeID = publisher, episode
				event.RecoveryRequired = true
				event.Cause = netproxy.WrapFailure(errors.New(cause), netproxy.Failure{Scope: netproxy.ScopeSharedResource,
					Layer: netproxy.LayerQUIC, Reason: netproxy.ReasonReset,
					Resource: netproxy.ResourceRef{OwnerID: publisher, ResourceID: episode, Generation: 1}})
				transport.state.Publish(event)
				c.handleSessionEvent(transport.Snapshot())

				c.dispatch()
			}
			publish(100, 7, "resource A reset")
			if c.cancel == nil || c.runningKind != checkCapacity || !finishCheck(c, <-c.results) {
				t.Fatal("first pool failure did not start replenishment")
			}
			deadline := d.RuntimeStatus().Recovery.RetryAt
			if deadline.IsZero() {
				t.Fatal("replacement failure did not schedule backoff")
			}
			first := *d.RuntimeStatus().Failure
			publish(100, 7, "repeated resource A diagnostic")
			if got := d.RuntimeStatus(); got.Failure == nil || *got.Failure != first || failures() != 1 || got.Recovery.RetryAt != deadline {
				t.Fatalf("repeated episode changed its first cause, count, or timer: %+v", got)
			}
			publisherB, episodeB := uint64(100), uint64(8)
			if separatePublishers {
				publisherB, episodeB = 200, 1
			}
			publish(publisherB, episodeB, "resource B reset")
			current := *d.RuntimeStatus().Failure
			if current.Message != "resource B reset" || failures() != 2 {
				t.Fatalf("independent resource incident was lost: %+v, failures=%v", current, failures())
			}
			publish(100, 7, "late resource A diagnostic")
			got := d.RuntimeStatus()
			if got.Failure == nil || *got.Failure != current {
				t.Fatalf("interleaved old episode replaced current failure: %+v -> %+v", current, got.Failure)
			}
			if failures() != 2 {
				t.Fatalf("interleaved old episode was counted again: %v", failures())
			}
			if !got.Healthy || got.Recovery.RetryAt != deadline || transport.connects.Load() != 1 || c.cancel != nil {
				t.Fatalf("interleaved old episode changed replenishment or health: %+v", got)
			}
			// Resolving an episode must not let a later diagnostic resurrect it.
			event = transport.Snapshot()
			event.PublisherID, event.EpisodeID = publisherB, episodeB
			event.Cause, event.RecoveryRequired = nil, false
			transport.state.Publish(event)
			c.handleSessionEvent(transport.Snapshot())

			c.dispatch()
			if d.RuntimeStatus().Failure != nil {
				t.Fatal("resolved pool retained its failure")
			}
			// This is only an old diagnostic; the owner reports no new demand.
			event = transport.Snapshot()
			event.PublisherID, event.EpisodeID = 100, 7
			event.Cause = netproxy.WrapFailure(errors.New("old resolved reset"), netproxy.Failure{Scope: netproxy.ScopeSharedResource})
			transport.state.Publish(event)
			c.handleSessionEvent(transport.Snapshot())

			c.dispatch()
			if got := d.RuntimeStatus(); got.Failure != nil || failures() != 2 || !got.Healthy || c.cancel != nil {
				t.Fatalf("resolved episode was resurrected: %+v, failures=%v", got, failures())
			}
		})
	}
}

func TestResourceEpisodeWatermarksBoundedByPublisher(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	for generation := uint64(1); generation <= 1000; generation++ {
		for publisher := uint64(1); publisher <= 2; publisher++ {
			event := transport.Snapshot()
			event.PublisherID, event.EpisodeID = publisher, generation
			event.Resource = netproxy.ResourceRef{OwnerID: publisher, ResourceID: publisher, Generation: generation}
			event.Cause = netproxy.WrapFailure(errors.New("resource reset"), netproxy.Failure{Scope: netproxy.ScopeSharedResource,
				Resource: netproxy.ResourceRef{OwnerID: generation + 100, ResourceID: generation + 200, Generation: 1}})
			transport.state.Publish(event)
			d.applySessionState(transport.Snapshot())
		}
	}
	if len(d.resourceFailures) != 2 {
		t.Fatalf("reconnect history grew beyond configured publishers: %d", len(d.resourceFailures))
	}
	current := *d.RuntimeStatus().Failure
	event := transport.Snapshot()
	event.PublisherID = 1
	event.Resource = netproxy.ResourceRef{OwnerID: 1, ResourceID: 1, Generation: 999}
	event.EpisodeID = 1001
	event.Cause = netproxy.WrapFailure(errors.New("late old generation"), netproxy.Failure{Scope: netproxy.ScopeSharedResource})
	transport.state.Publish(event)
	d.applySessionState(transport.Snapshot())
	if got := *d.RuntimeStatus().Failure; got != current {
		t.Fatalf("old generation with a new diagnostic episode rewrote current cause: %+v", got)
	}
}

func TestUncheckedSessionStillRecoversWithoutProbing(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	d := newTestDialer(t, transport)
	d.checksConnectivity = false
	d.recovery.Verification = "disabled"
	for i := range d.networks {
		d.networks[i] = networkSupported
	}
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{d.StatsKey(): {Name: d.Name}}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	start := make(chan struct{})
	close(start)
	d.ActivateCheck(start)
	state := waitRecoveryPhase(t, d, RecoveryReady)
	if !d.RuntimeStatus().Healthy || state.Verification != "disabled" {
		t.Fatalf("unchecked ready = %+v", d.RuntimeStatus())
	}
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("session lost"))
	deadline := time.Now().Add(time.Second)
	for transport.connects.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	waitRecoveryPhase(t, d, RecoveryReady)
	if transport.connects.Load() < 2 || stats.DefaultStore.GetNode(d.StatsKey()).ChecksTotal != 0 {
		t.Fatal("disabled health checks stopped liveness recovery or ran a probe")
	}
}
