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

type testCapacityTransport struct {
	*testSessionTransport
	targetCapacity int
}

func (t *testCapacityTransport) Connect(context.Context) error {
	t.connects.Add(1)
	if t.connectErr != nil {
		return t.connectErr
	}
	event := t.Snapshot()
	event.RecoveryPhase = "ready"
	event.Cause = nil
	event.UsableCapacity++
	event.RecoveryRequired = event.UsableCapacity < t.targetCapacity
	t.state.Publish(event)
	return nil
}

func TestHealthyCapacityRecoveryKeepsHealthAndDeduplicatesDemand(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryExecutor = netproxy.RecoveryDaemon
	event.RecoveryRequired = true
	event.Cause = netproxy.WrapFailure(errors.New("lost pool slot"), netproxy.Failure{Scope: netproxy.ScopeSharedResource,
		Resource: netproxy.ResourceRef{OwnerID: 1, ResourceID: 2, Generation: 3}, Reason: netproxy.ReasonReset})
	transport.state.Publish(event)
	transport.connectErr = errors.New("replacement dial failed")
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{d.StatsKey(): {Name: d.Name}}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	c := testRecoveryChecker(t, d)
	c.handleSessionEvent(transport.Snapshot())

	c.dispatch()
	if c.cancel == nil || c.runningKind != checkCapacity {
		t.Fatal("healthy pool did not request background replenishment")
	}
	if !finishCheck(c, <-c.results) {
		t.Fatal("checker stopped")
	}
	state := d.RuntimeStatus()
	if !state.Healthy || state.ConfirmingFailure || state.Recovery.Phase != RecoveryBackoff || state.Recovery.Action != "replenish" || state.Recovery.RetryAt.IsZero() {
		t.Fatalf("capacity failure invalidated serving siblings or lost its timer: %+v", state)
	}
	if state.Availability.ChecksTotal != 0 || d.connectivityCheckRequested() {
		t.Fatal("capacity failure became a node health check")
	}
	deadline := state.Recovery.RetryAt
	for i := 0; i < 20; i++ {
		event := transport.Snapshot()
		event.RecoveryPhase = "capacity_wait"
		transport.state.Publish(event)
		c.handleSessionEvent(transport.Snapshot())

		c.dispatch()
	}
	if transport.connects.Load() != 1 || c.cancel != nil || d.RuntimeStatus().Recovery.RetryAt != deadline {
		t.Fatal("repeated capacity demand reset backoff or duplicated Connect")
	}
	c.updateHealthSchedule(true)
	c.dispatch()
	if got := d.RuntimeStatus().Recovery; got.Action != "replenish" || got.RetryAt != deadline {
		t.Fatalf("health check hid background replenishment: %+v", got)
	}
	transport.connectErr = nil
	c.timer.Stop()
	c.capacityAt = time.Time{}
	c.dispatch()
	result := <-c.results
	c.handleSessionEvent(transport.Snapshot())

	c.dispatch()
	if !finishCheck(c, result) {
		t.Fatal("checker stopped")
	}
	state = d.RuntimeStatus()
	if !state.Healthy || state.Failure != nil || state.Recovery.Phase != RecoveryReady || !state.Recovery.RetryAt.IsZero() || transport.connects.Load() != 2 {
		t.Fatalf("capacity recovery did not finish: %+v", state)
	}
}

func TestCapacityAuthFailureKeepsServingUntilEnvironmentRequest(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	transport.connectErr = netproxy.WrapFailure(errors.New("replacement credentials rejected"), netproxy.Failure{Reason: netproxy.ReasonAuth})
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	c := testRecoveryChecker(t, d)
	c.handleSessionEvent(transport.Snapshot())

	c.dispatch()
	finishCheck(c, <-c.results)
	state := d.RuntimeStatus()
	if !state.Healthy || state.Recovery.Phase != RecoveryBlocked || state.Recovery.Action != "replenish" || !state.Recovery.RetryAt.IsZero() {
		t.Fatalf("blocked capacity work changed serving health or scheduled a retry: %+v", state)
	}
	if state.Failure == nil || state.Failure.Reason != netproxy.ReasonAuth {
		t.Fatalf("blocked capacity work lost authentication detail: %+v", state.Failure)
	}
	c.handleSessionEvent(transport.Snapshot())

	c.dispatch()
	c.updateSchedule(checkHealth, appliedCheck{success: true})
	if c.cancel != nil || transport.connects.Load() != 1 || d.RuntimeStatus().Recovery.Phase != RecoveryBlocked {
		t.Fatal("Session diagnostic or successful probe restarted blocked capacity work")
	}
	// A successful health check verifies serving slots; it does not repair the
	// credentials used to open replacement slots.
	c.start(checkHealth)
	finishCheck(c, <-c.results)
	if failure := d.RuntimeStatus().Failure; failure == nil || failure.Reason != netproxy.ReasonAuth {
		t.Fatalf("successful health probe hid blocked replenishment: %+v", failure)
	}
	event = transport.Snapshot()
	event.RecoveryPhase = "capacity_wait"
	transport.state.Publish(event)
	c.handleSessionEvent(transport.Snapshot())
	c.dispatch()
	if failure := d.RuntimeStatus().Failure; failure == nil || failure.Reason != netproxy.ReasonAuth {
		t.Fatalf("capacity state update hid authentication detail: %+v", failure)
	}

	transport.connectErr = nil
	d.RequestConnectivityCheck()
	c.start(c.requestedCheckKind())
	finishCheck(c, <-c.results)
	if c.cancel == nil || c.runningKind != checkCapacity {
		t.Fatal("environment request did not restart capacity replenishment")
	}
	result := <-c.results
	c.handleSessionEvent(transport.Snapshot())

	c.dispatch()
	finishCheck(c, result)
	if state := d.RuntimeStatus(); !state.Healthy || state.Failure != nil || state.Recovery.Phase != RecoveryReady || transport.connects.Load() != 2 {
		t.Fatalf("capacity did not recover after environment request: %+v", state)
	}
}

func TestCapacityBackoffDeadlineMatchesItsTimer(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	c := testRecoveryChecker(t, d)
	c.capacityInterval = time.Millisecond
	c.finishCapacity(checkResult{kind: checkCapacity, connectErr: errors.New("failed")}, true)
	c.dispatch()
	snapshot := d.RuntimeStatus().Recovery
	select {
	case fired := <-c.timer.C:
		if delta := fired.Sub(snapshot.RetryAt); delta < -time.Millisecond || delta > time.Millisecond {
			t.Fatalf("capacity timer differs from displayed deadline by %s", delta)
		}
	case <-time.After(time.Second):
		t.Fatal("capacity retry did not fire")
	}
}

func TestRecoverySerializesDueHealthCapacityAndSupport(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	d.health.networks[common.NetworkUDP4] = networkUnknown

	started, release := make(chan struct{}), make(chan struct{})
	c := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, network *common.NetworkType) error {
		if network.Index() == common.NetworkTCP4 {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return netproxy.UnsupportedTunnelTypeError
	})
	t.Cleanup(c.stopRetries)
	c.healthAt = time.Now().Add(-time.Second)
	c.supportAt = c.healthAt
	c.dispatch()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("due health check did not start")
	}
	c.handleSessionEvent(transport.Snapshot())
	c.dispatch()
	if c.runningKind != checkHealth || transport.connects.Load() != 0 {
		t.Fatal("another operation started during the health probe")
	}

	close(release)
	finishCheck(c, <-c.results)
	if c.cancel == nil || c.runningKind != checkCapacity {
		t.Fatal("healthy node did not replenish before capability discovery")
	}
	result := <-c.results
	c.handleSessionEvent(transport.Snapshot())
	finishCheck(c, result)
	if c.cancel == nil || c.runningKind != checkSupport {
		t.Fatal("overdue capability discovery was lost while other work ran")
	}
	finishCheck(c, <-c.results)
	if c.cancel != nil || transport.connects.Load() != 1 || !d.RuntimeStatus().Healthy ||
		d.networkStates()[common.NetworkUDP4] != networkUnsupported {
		t.Fatal("scheduled work was duplicated or changed serving health")
	}
}

func TestCapacityProgressDoesNotBackOff(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected), targetCapacity: 4}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	c := testRecoveryChecker(t, d)
	c.capacityInterval = time.Minute
	c.dispatch()
	for range 3 {
		if c.cancel == nil || c.runningKind != checkCapacity {
			t.Fatal("successful partial replenishment entered backoff instead of filling the pool")
		}
		finishCheck(c, <-c.results)
	}
	if c.cancel != nil || c.capacityInterval != 0 || transport.Snapshot().RecoveryRequired || transport.connects.Load() != 3 {
		t.Fatal("pool did not finish replenishing with one operation per missing slot")
	}
}

func TestCapacityReplacementLostBeforeCompletionBacksOff(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	c := testRecoveryChecker(t, d)
	c.healthAt = time.Now().Add(time.Hour)
	for i := range 3 {
		c.dispatch()
		if c.cancel == nil || c.runningKind != checkCapacity {
			t.Fatal("missing capacity did not start a replacement")
		}
		result := <-c.results
		// A slot may become ready, then immediately close or receive GOAWAY.
		// The worker consumes both events before the completed operation.
		c.handleSessionEvent(transport.Snapshot())
		event = transport.Snapshot()
		event.UsableCapacity--
		event.RecoveryRequired = true
		event.EpisodeID++
		transport.state.Publish(event)
		c.handleSessionEvent(transport.Snapshot())
		finishCheck(c, result)
		if c.cancel != nil || !c.capacityAt.After(time.Now()) || c.capacityInterval != time.Second<<i {
			t.Fatalf("replacement loss bypassed backoff: running=%v retry=%v interval=%s", c.cancel != nil, c.capacityAt, c.capacityInterval)
		}
		if !d.RuntimeStatus().Healthy {
			t.Fatal("failed replenishment invalidated healthy sibling slots")
		}
		c.capacityAt = time.Time{} // Advance just the capacity deadline.
	}
	c.dispatch()
	finishCheck(c, <-c.results)
	if c.cancel != nil || c.capacityInterval != 0 || transport.Snapshot().RecoveryRequired {
		t.Fatal("a surviving replacement did not clear the retry backoff")
	}
}

func TestUnhealthyPartialPoolReplenishesBeforeReverification(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	d.mu.Lock()
	d.confirmFailureLocked()
	d.health.phase = healthUnhealthy
	d.mu.Unlock()
	c := testRecoveryChecker(t, d)
	c.healthAt = time.Now().Add(time.Hour)
	c.dispatch()
	if c.cancel == nil || c.runningKind != checkCapacity {
		t.Fatal("failed health prevented repair of an accepting partial pool")
	}
	c.finish(<-c.results)
	if d.RuntimeStatus().Healthy {
		t.Fatal("capacity repair fabricated a successful health proof")
	}
	c.dispatch()
	if c.cancel == nil || c.runningKind != checkHealth {
		t.Fatal("capacity repair left verification behind the old health backoff")
	}
	finishCheck(c, <-c.results)
	if status := d.RuntimeStatus(); !status.Healthy || !status.Degraded || status.RecoveryElapsed != 0 {
		t.Fatalf("first verified repair did not start a degraded recovery window: %+v", status)
	}
}

func TestSelectedPausedPathRepairsCapacityWithoutPeriodicProbes(t *testing.T) {
	transport := &testCapacityTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	d.SetSelected(true)
	d.SetMonitoring(false)
	c := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
		t.Error("capacity repair enabled periodic probes on a paused path")
		return nil
	})
	t.Cleanup(c.stopRetries)
	c.healthAt = time.Now()
	c.dispatch()
	if c.cancel == nil || c.runningKind != checkCapacity {
		t.Fatal("a selected path's paused latency checks prevented capacity repair")
	}
	finishCheck(c, <-c.results)
	if c.cancel != nil || transport.connects.Load() != 1 || !c.healthAt.IsZero() {
		t.Fatal("capacity completion restarted periodic health checks")
	}
}
