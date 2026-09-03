/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

type testTransport struct{}

func (testTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (testTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type testSessionTransport struct {
	state    *netproxy.StateBroadcaster
	connects atomic.Int32
}

func newTestSessionTransport(state netproxy.SessionState) *testSessionTransport {
	return &testSessionTransport{state: netproxy.NewStateBroadcaster(state)}
}

func (d *testSessionTransport) Connect(context.Context) error {
	d.connects.Add(1)
	d.state.Transition(netproxy.SessionConnecting, nil)
	d.state.Transition(netproxy.SessionConnected, nil)
	return nil
}

func (d *testSessionTransport) Snapshot() netproxy.StateEvent { return d.state.Snapshot() }

func (d *testSessionTransport) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.state.WatchState(ctx)
}

func (d *testSessionTransport) Close() error {
	d.state.Transition(netproxy.SessionClosed, nil)
	return nil
}

func (*testSessionTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (*testSessionTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type testGroup struct {
	changes   atomic.Int32
	forces    atomic.Int32
	forceMask atomic.Uint32
}

func (g *testGroup) DialerChanged(_ *Dialer, force SelectionForceMask) {
	g.changes.Add(1)
	if force != SelectionForceNone {
		g.forces.Add(1)
		g.forceMask.Store(uint32(force))
	}
}

var testDialerSequence atomic.Uint64

func newTestDialer(t *testing.T, transport netproxy.Dialer) *Dialer {
	t.Helper()
	layer := netproxy.Layer{Data: transport}
	if session, ok := transport.(*testSessionTransport); ok {
		layer.Sessions = []netproxy.Session{session}
		layer.Resources = []io.Closer{session}
	}
	id := testDialerSequence.Add(1)
	d := NewDialer(netproxy.NewRuntime(layer), &GlobalOption{
		CheckInterval:    time.Hour,
		CheckIntervalMax: time.Hour,
	}, &Property{
		Name: t.Name(),
		Link: fmt.Sprintf("test://%s/%d", t.Name(), id),
	}, InitialCheckBlocking, "")
	d.RegisterDialerGroup(new(testGroup), 0.5, time.Minute)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func checkProbe(probes [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error)) func(context.Context, *common.NetworkType) (bool, error) {
	return func(ctx context.Context, network *common.NetworkType) (bool, error) {
		probe := probes[network.Index()]
		if probe == nil {
			return false, errors.New("probe not configured")
		}
		return probe(ctx, network)
	}
}

func TestConnectivityCheckerWaitsForStartGate(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	probed := make(chan struct{}, 1)
	checker := newConnectivityChecker(d, func(_ context.Context, network *common.NetworkType) (bool, error) {
		if network.Index() == common.NetworkTCP4 {
			select {
			case probed <- struct{}{}:
			default:
			}
			return true, nil
		}
		return false, errors.New("probe not configured")
	})
	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		checker.run(start)
		close(done)
	}()

	select {
	case <-probed:
		t.Fatal("connectivity probe started before the shared gate opened")
	case <-time.After(20 * time.Millisecond):
	}
	close(start)
	select {
	case <-probed:
	case <-time.After(time.Second):
		t.Fatal("connectivity probe did not start after the shared gate opened")
	}
	_ = d.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connectivity checker did not stop after dialer close")
	}
}

func TestStatsKeyEncodingSeparatesIdentityAndScope(t *testing.T) {
	left := makeStatsKey(&Property{SubscriptionTag: "sub", Link: "a\x1fb"}, "c")
	right := makeStatsKey(&Property{SubscriptionTag: "sub", Link: "a"}, "b\x1fc")
	if left == right {
		t.Fatalf("structured stats keys collided: %q", left)
	}
	explicitChain := composeStatsIdentity("source", "a->b", "0")
	nextHopChain := composeStatsIdentity(
		"next-hop",
		composeStatsIdentity("source", "a", "0"),
		composeStatsIdentity("source", "b", "0"),
	)
	if explicitChain == nextHopChain {
		t.Fatalf("explicit and next-hop chains collided: %q", explicitChain)
	}
}

func TestStatsPathUsesDialerIdentity(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	path := d.StatsPath("group", common.NetworkUDP6.NetworkType())
	if path.NodeID != d.StatsID() || path.Outbound != "group" ||
		path.Subtag != d.Property.SubscriptionTag || path.Dialer != d.Name ||
		path.Network != common.NetworkUDP6 {
		t.Fatalf("stats path = %+v", path)
	}
}

func TestUncheckedDialerRecordsAvailabilityOnlyWhenActivated(t *testing.T) {
	id := testDialerSequence.Add(1)
	d := NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: testTransport{}}), &GlobalOption{}, &Property{
		Name: t.Name(),
		Link: fmt.Sprintf("test://%s/%d", t.Name(), id),
	}, InitialCheckDisabled, "")
	t.Cleanup(func() { _ = d.Close() })
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{
		d.StatsKey(): {Subtag: d.Property.SubscriptionTag, Name: d.Name},
	}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	if availability := stats.DefaultStore.GetNode(d.StatsKey()); availability.Seen {
		t.Fatalf("candidate dialer published availability: %+v", availability)
	}

	start := make(chan struct{})
	close(start)
	d.ActivateCheck(start)
	if availability := stats.DefaultStore.GetNode(d.StatsKey()); !availability.Seen || !availability.Alive {
		t.Fatalf("activated unchecked dialer availability = %+v", availability)
	}
}

func TestInitialCheckClassifiesOnlyExplicitUnsupported(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	probes := [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error){
		func(context.Context, *common.NetworkType) (bool, error) { return true, nil },
		func(context.Context, *common.NetworkType) (bool, error) { return false, context.DeadlineExceeded },
		func(context.Context, *common.NetworkType) (bool, error) {
			return false, fmt.Errorf("wrapped: %w", netproxy.UnsupportedTunnelTypeError)
		},
		func(context.Context, *common.NetworkType) (bool, error) {
			return false, errors.New("network is unreachable")
		},
	}
	checker := newConnectivityChecker(d, checkProbe(probes))
	result := checker.perform(context.Background(), checkInitial)
	applied, accepted := d.applyCheck(result)
	if !accepted || !applied.success {
		t.Fatalf("initial result = %+v", applied)
	}
	if !d.ConnectivitySnapshot().InitialCheckDone {
		t.Fatal("completed initial result was not retained by the dialer")
	}
	want := [common.NetworkTypeCount]NetworkSupportState{
		NetworkSupportConfirmed,
		NetworkSupportUnknown,
		NetworkSupportUnsupported,
		NetworkSupportUnknown,
	}
	status := d.RuntimeStatus()
	if got := status.SupportState; got != want {
		t.Fatalf("support = %v, want %v", got, want)
	}
	if !d.Usable(common.NetworkTCP4.NetworkType()) || d.Usable(common.NetworkTCP6.NetworkType()) {
		t.Fatal("runtime usability does not match health and support")
	}
	if got := d.group.observer.(*testGroup).forces.Load(); got != 1 {
		t.Fatalf("initial forced group refreshes = %d, want 1", got)
	}
	if got := SelectionForceMask(d.group.observer.(*testGroup).forceMask.Load()); got != SelectionForceFor(common.NetworkTCP4) {
		t.Fatalf("initial force mask = %04b, want tcp4", got)
	}
}

func TestPendingInitialCheckIsNotReportedComplete(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	applied, accepted := d.applyCheck(checkResult{
		kind: checkInitial,
		probes: []probeResult{{
			network: common.NetworkTCP4,
			err:     context.DeadlineExceeded,
		}},
	})
	if !accepted {
		t.Fatalf("pending initial result = %+v", applied)
	}
	if d.ConnectivitySnapshot().InitialCheckDone {
		t.Fatal("pending initial result was marked complete")
	}
}

func TestUnsupportedInitialCheckIsComplete(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	var probes [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error)
	for i := range probes {
		probes[i] = func(context.Context, *common.NetworkType) (bool, error) {
			return false, netproxy.UnsupportedTunnelTypeError
		}
	}
	result := newConnectivityChecker(d, checkProbe(probes)).perform(context.Background(), checkInitial)
	applied, accepted := d.applyCheck(result)
	if !accepted || applied.success {
		t.Fatalf("unsupported initial result = %+v", applied)
	}
	if !d.ConnectivitySnapshot().InitialCheckDone {
		t.Fatal("unsupported initial result was not marked complete")
	}
	if got := d.group.observer.(*testGroup).forces.Load(); got != 0 {
		t.Fatalf("unsupported initial result forced selection: %d", got)
	}
}

func TestInitialCheckLogsEveryModeAndSupportDiscovery(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput := logger.Out
	previousLevel := logger.Level
	previousFormatter := logger.Formatter
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetLevel(log.DebugLevel)
	logger.SetFormatter(new(log.JSONFormatter))
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetLevel(previousLevel)
		logger.SetFormatter(previousFormatter)
	})

	d := newTestDialer(t, testTransport{})
	var probes [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error)
	for i := range probes {
		index := common.NetworkIndex(i)
		probes[i] = func(context.Context, *common.NetworkType) (bool, error) {
			if index == common.NetworkTCP6 {
				return true, nil
			}
			return false, errors.New("probe failed")
		}
	}
	result := newConnectivityChecker(d, checkProbe(probes)).perform(context.Background(), checkInitial)
	if _, accepted := d.applyCheck(result); !accepted {
		t.Fatal("initial result was rejected")
	}
	logs := output.String()
	if got := strings.Count(logs, `"msg":"Connectivity initial check`); got != common.NetworkTypeCount {
		t.Fatalf("initial result logs = %d, want %d\n%s", got, common.NetworkTypeCount, logs)
	}
	if got := strings.Count(logs, `"msg":"Connectivity mode supported"`); got != 1 {
		t.Fatalf("support discovery logs = %d, want 1\n%s", got, logs)
	}
}

func TestInitialCheckPublishesOnlyAfterFullSweep(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	blocked := make(chan struct{})
	started := make(chan struct{})
	var probes [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error)
	for i := range probes {
		probes[i] = func(context.Context, *common.NetworkType) (bool, error) { return true, nil }
	}
	probes[common.NetworkUDP4] = func(context.Context, *common.NetworkType) (bool, error) {
		close(started)
		<-blocked
		return true, nil
	}
	checker := newConnectivityChecker(d, checkProbe(probes))
	resultCh := make(chan checkResult, 1)
	go func() { resultCh <- checker.perform(context.Background(), checkInitial) }()
	<-started
	for index, state := range d.networkStates() {
		if state != networkUntested {
			t.Fatalf("network %d was published before the full sweep: %v", index, state)
		}
	}
	group := d.group.observer.(*testGroup)
	if got := group.changes.Load(); got != 0 {
		t.Fatalf("group changes before full sweep = %d", got)
	}
	close(blocked)
	result := <-resultCh
	if got := group.changes.Load(); got != 0 {
		t.Fatalf("probe execution published group changes = %d", got)
	}
	if _, accepted := d.applyCheck(result); !accepted {
		t.Fatal("full initial sweep was rejected")
	}
	if got := group.changes.Load(); got != 1 {
		t.Fatalf("group changes after full sweep = %d, want 1", got)
	}
}

func TestSupportRetryBackoffAndJitter(t *testing.T) {
	interval := supportRetryInitialInterval
	want := []time.Duration{
		8 * time.Second,
		32 * time.Second,
		2*time.Minute + 8*time.Second,
		8*time.Minute + 32*time.Second,
		34*time.Minute + 8*time.Second,
		time.Hour,
		time.Hour,
	}
	for i, expected := range want {
		interval = nextRetryInterval(interval, time.Hour)
		if interval != expected {
			t.Fatalf("retry interval %d = %v, want %v", i, interval, expected)
		}
	}
	if got := initialRetryInterval(time.Second); got != time.Second {
		t.Fatalf("capped initial interval = %v, want 1s", got)
	}
	for i := 0; i < 100; i++ {
		got := jitterCheckInterval(10 * time.Second)
		if got < 8*time.Second || got > 12*time.Second {
			t.Fatalf("jittered interval = %v, want [8s, 12s]", got)
		}
		got = jitterRetryInterval(time.Hour, time.Hour)
		if got < 48*time.Minute || got > time.Hour {
			t.Fatalf("capped jittered interval = %v, want [48m, 1h]", got)
		}
	}
}

func TestSupportRetryRemainsPendingWhenAnotherModeIsSupported(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	for i := range d.networks {
		d.networks[i] = networkUnsupported
	}
	d.networks[common.NetworkTCP6] = networkSupported
	d.networks[common.NetworkTCP4] = networkUnknown
	d.healthy = true
	d.mu.Unlock()
	checker := newConnectivityChecker(d, checkProbe([common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error){}))
	if !checker.supportPending() {
		t.Fatal("unknown mode was not scheduled while another mode was supported")
	}
}

func TestExplicitRequestResetsSupportRetryWithoutCanonicalMode(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	for i := range d.networks {
		d.networks[i] = networkUnknown
	}
	d.mu.Unlock()
	checker := newConnectivityChecker(d, checkProbe([common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error){}))
	t.Cleanup(func() {
		checker.healthTimer.Stop()
		checker.supportTimer.Stop()
	})
	checker.retryInterval = time.Hour
	checker.scheduleSupport()
	d.RequestConnectivityCheck()
	checker.requestHealth()
	if checker.retryInterval != supportRetryInitialInterval || !checker.supportScheduled {
		t.Fatalf("support retry after request = %v, scheduled=%v", checker.retryInterval, checker.supportScheduled)
	}
	if d.connectivityCheckRequested() {
		t.Fatal("explicit connectivity request was not consumed")
	}
}

func TestSupportDiscoveryUsesNewCanonicalResult(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput := logger.Out
	previousFormatter := logger.Formatter
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(new(log.JSONFormatter))
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetFormatter(previousFormatter)
	})

	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	for i := range d.networks {
		d.networks[i] = networkUnsupported
	}
	d.networks[common.NetworkTCP6] = networkUnknown
	d.networks[common.NetworkTCP4] = networkSupported
	d.healthy = false
	d.checkRequested = true
	d.mu.Unlock()
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{
		d.StatsKey(): {Subtag: d.SubscriptionTag, Name: d.Name},
	}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	group := d.group.observer.(*testGroup)
	applied, accepted := d.applyCheck(checkResult{
		kind:   checkSupport,
		probes: []probeResult{{network: common.NetworkTCP6, latency: time.Millisecond}},
	})
	if !accepted || !applied.success || !applied.healthApplied || !applied.requested {
		t.Fatalf("support discovery = %+v, accepted=%v", applied, accepted)
	}
	if got := group.forces.Load(); got != 1 {
		t.Fatalf("support discovery forced refreshes = %d, want 1", got)
	}
	if got := SelectionForceMask(group.forceMask.Load()); got != SelectionForceFor(common.NetworkTCP6) {
		t.Fatalf("support discovery force mask = %04b, want tcp6", got)
	}
	if got := strings.Count(output.String(), `"msg":"Connectivity mode supported"`); got != 1 {
		t.Fatalf("support discovery logs = %d, want 1\n%s", got, output.String())
	}
	if latency, ok := d.latencyStats(); !ok || latency.Last != time.Millisecond {
		t.Fatalf("support canonical latency = %+v, %v; want 1ms", latency, ok)
	}
	availability := stats.DefaultStore.GetNode(d.StatsKey())
	if !availability.Alive || availability.ChecksTotal != 1 || availability.LastCheckAt.IsZero() {
		t.Fatalf("support canonical availability = %+v", availability)
	}
	checker := newConnectivityChecker(d, nil)
	t.Cleanup(func() {
		checker.healthTimer.Stop()
		checker.supportTimer.Stop()
	})
	checker.healthDue = true
	checker.updateSchedule(checkSupport, applied)
	if checker.healthDue {
		t.Fatal("canonical support result left a duplicate health check pending")
	}

	if _, accepted := d.applyCheck(checkResult{
		kind:   checkSupport,
		probes: []probeResult{{network: common.NetworkTCP6, err: netproxy.UnsupportedTunnelTypeError}},
	}); !accepted {
		t.Fatal("unchanged support result was rejected")
	}
	if got := group.forces.Load(); got != 1 {
		t.Fatalf("unchanged support forced refresh: %d", got)
	}
	if got := strings.Count(output.String(), `"msg":"Connectivity mode supported"`); got != 1 {
		t.Fatalf("support discovery was logged more than once: %d", got)
	}
	if state := d.networkStates()[common.NetworkTCP6]; state != networkSupported {
		t.Fatalf("duplicate support result changed terminal state to %v", state)
	}
	if latency, _ := d.latencyStats(); latency.Last != time.Millisecond {
		t.Fatalf("duplicate support result changed latency to %v", latency.Last)
	}
	d.mu.Lock()
	d.networks[common.NetworkTCP4] = networkUnsupported
	d.mu.Unlock()
	d.applyCheck(checkResult{kind: checkSupport, probes: []probeResult{{network: common.NetworkTCP4}}})
	if state := d.networkStates()[common.NetworkTCP4]; state != networkUnsupported {
		t.Fatalf("duplicate probe changed unsupported terminal state to %v", state)
	}
}

func TestNonCanonicalSupportDiscoveryForcesOnlyDiscoveredMode(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	for i := range d.networks {
		d.networks[i] = networkUnsupported
	}
	d.networks[common.NetworkTCP6] = networkSupported
	d.networks[common.NetworkTCP4] = networkUnknown
	d.healthy = true
	d.mu.Unlock()
	group := d.group.observer.(*testGroup)
	applied, accepted := d.applyCheck(checkResult{
		kind: checkSupport,
		probes: []probeResult{{
			network: common.NetworkTCP4,
		}},
	})
	if !accepted || !applied.success || applied.healthApplied {
		t.Fatalf("non-canonical support result = %+v, accepted=%v", applied, accepted)
	}
	if got := SelectionForceMask(group.forceMask.Load()); got != SelectionForceFor(common.NetworkTCP4) {
		t.Fatalf("non-canonical support force mask = %04b, want tcp4", got)
	}
}

func TestNonCanonicalSupportWaitsForCanonicalRecovery(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	for i := range d.networks {
		d.networks[i] = networkUnsupported
	}
	d.networks[common.NetworkTCP6] = networkSupported
	d.networks[common.NetworkTCP4] = networkUnknown
	d.networks[common.NetworkUDP4] = networkUnknown
	d.healthy = false
	d.mu.Unlock()
	group := d.group.observer.(*testGroup)
	support, accepted := d.applyCheck(checkResult{
		kind: checkSupport,
		probes: []probeResult{
			{network: common.NetworkTCP4},
			{network: common.NetworkUDP4},
		},
	})
	wantForce := SelectionForceFor(common.NetworkTCP4) | SelectionForceFor(common.NetworkUDP4)
	if !accepted || support.success || d.pendingForce != wantForce {
		t.Fatalf("support result while unhealthy = %+v, accepted=%v", support, accepted)
	}
	if got := group.forces.Load(); got != 0 {
		t.Fatalf("unhealthy support forced selection: %d", got)
	}
	checker := newConnectivityChecker(d, func(context.Context, *common.NetworkType) (bool, error) { return true, nil })
	t.Cleanup(func() {
		checker.healthTimer.Stop()
		checker.supportTimer.Stop()
	})
	checker.updateSchedule(checkSupport, support)
	if failed, accepted := d.applyCheck(checkResult{
		kind:   checkHealth,
		probes: []probeResult{{network: common.NetworkTCP6, err: errors.New("still down")}},
	}); !accepted || failed.success || d.pendingForce != wantForce {
		t.Fatalf("failed canonical retry changed pending force: %+v, accepted=%v", failed, accepted)
	}
	d.applySessionState(netproxy.StateEvent{Seq: 1, State: netproxy.SessionDisconnected})
	if d.pendingForce != wantForce {
		t.Fatalf("session loss changed pending force to %04b", d.pendingForce)
	}
	healthResult := checker.perform(context.Background(), checkHealth)
	health, accepted := d.applyCheck(healthResult)
	if !accepted || !health.success || d.pendingForce != SelectionForceNone {
		t.Fatalf("canonical recovery = %+v, accepted=%v", health, accepted)
	}
	if !d.Usable(common.NetworkTCP6.NetworkType()) || !d.Usable(common.NetworkTCP4.NetworkType()) || !d.Usable(common.NetworkUDP4.NetworkType()) {
		t.Fatal("supported modes did not follow canonical recovery")
	}
	if got := SelectionForceMask(group.forceMask.Load()); got != wantForce {
		t.Fatalf("canonical recovery force mask = %04b, want %04b", got, wantForce)
	}
}

func TestCanonicalModeUsesFirstSupportedState(t *testing.T) {
	states := [common.NetworkTypeCount]networkState{}
	states[common.NetworkTCP6] = networkUnknown
	states[common.NetworkTCP4] = networkSupported
	states[common.NetworkUDP6] = networkSupported
	states[common.NetworkUDP4] = networkUnsupported
	if got := firstSupportedNetwork(states); got != common.NetworkTCP4 {
		t.Fatalf("canonical mode = %v, want tcp4", got)
	}
	states[common.NetworkTCP6] = networkSupported
	if got := firstSupportedNetwork(states); got != common.NetworkTCP6 {
		t.Fatalf("canonical mode after discovery = %v, want tcp6", got)
	}
}

func TestInitialCheckRecordsOnlyCanonicalLatency(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	_, accepted := d.applyCheck(checkResult{
		kind: checkInitial,
		probes: []probeResult{
			{network: common.NetworkTCP4, latency: time.Millisecond},
			{network: common.NetworkTCP6, latency: 50 * time.Millisecond},
		},
	})
	if !accepted {
		t.Fatal("initial result was rejected")
	}
	latency, ok := d.latencyStats()
	if !ok || latency.Last != 50*time.Millisecond {
		t.Fatalf("canonical latency = %+v, %v; want 50ms", latency, ok)
	}
}

func TestHealthCheckUsesOnlyCanonicalMode(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	d.healthy = true
	d.networks[common.NetworkTCP6] = networkSupported
	d.networks[common.NetworkTCP4] = networkSupported
	d.mu.Unlock()
	var canonicalCalls, alternativeCalls atomic.Int32
	var probes [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error)
	probes[common.NetworkTCP6] = func(context.Context, *common.NetworkType) (bool, error) {
		canonicalCalls.Add(1)
		return false, errors.New("canonical probe failed")
	}
	probes[common.NetworkTCP4] = func(context.Context, *common.NetworkType) (bool, error) {
		alternativeCalls.Add(1)
		return true, nil
	}
	checker := newConnectivityChecker(d, checkProbe(probes))
	result := checker.perform(context.Background(), checkHealth)
	applied, _ := d.applyCheck(result)
	if applied.success {
		t.Fatalf("health result = %+v", applied)
	}
	if got := canonicalCalls.Load(); got != 2 {
		t.Fatalf("canonical probes = %d, want 2", got)
	}
	if got := alternativeCalls.Load(); got != 0 {
		t.Fatalf("alternative probes = %d, want 0", got)
	}
	if d.SelectionSnapshot(common.NetworkTCP6.NetworkType()).Usable {
		t.Fatal("failed canonical mode remained usable")
	}
	if d.SelectionSnapshot(common.NetworkTCP4.NetworkType()).Usable {
		t.Fatal("supported alternative did not follow canonical health failure")
	}
	status := d.RuntimeStatus()
	if status.SupportState[common.NetworkTCP6] != NetworkSupportConfirmed || status.SupportState[common.NetworkTCP4] != NetworkSupportConfirmed {
		t.Fatalf("health failure changed confirmed support: %v", status.SupportState)
	}
	if got := firstSupportedNetwork(d.networkStates()); got != common.NetworkTCP6 {
		t.Fatalf("canonical mode migrated to %v, want tcp6", got)
	}
	latency, ok := d.latencyStats()
	if !ok || latency.Last != time.Minute || !latency.Avg10HasFailure {
		t.Fatalf("canonical failure latency = %+v, %v; want timeout penalty", latency, ok)
	}
	d.applyCheck(checkResult{
		kind: checkHealth,
		probes: []probeResult{{
			network: common.NetworkTCP6,
			latency: time.Millisecond,
		}},
	})
	if !d.Usable(common.NetworkTCP6.NetworkType()) || !d.Usable(common.NetworkTCP4.NetworkType()) {
		t.Fatal("supported modes did not follow canonical recovery")
	}
}

func TestSupportCheckReconnectsWithoutCanonicalMode(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	d := newTestDialer(t, transport)
	d.mu.Lock()
	for index := range d.networks {
		d.networks[index] = networkUnknown
	}
	d.mu.Unlock()

	probes := [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error){}
	for index := range probes {
		probes[index] = func(context.Context, *common.NetworkType) (bool, error) {
			return false, errors.New("unsupported for now")
		}
	}
	probes[common.NetworkTCP4] = func(context.Context, *common.NetworkType) (bool, error) {
		return true, nil
	}
	result := newConnectivityChecker(d, checkProbe(probes)).perform(context.Background(), checkSupport)
	applied, accepted := d.applyCheck(result)
	if !accepted || !applied.success || !applied.healthApplied {
		t.Fatalf("support result = %+v, accepted=%v", applied, accepted)
	}
	if got := transport.connects.Load(); got != 1 {
		t.Fatalf("session connects = %d, want 1", got)
	}
	if !d.Usable(common.NetworkTCP4.NetworkType()) {
		t.Fatal("support check did not make the discovered mode usable")
	}
}

func TestHealthLoggingUsesStateTransitions(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput := logger.Out
	previousLevel := logger.Level
	previousFormatter := logger.Formatter
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetLevel(log.DebugLevel)
	logger.SetFormatter(new(log.JSONFormatter))
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetLevel(previousLevel)
		logger.SetFormatter(previousFormatter)
	})

	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	for i := range d.networks {
		d.networks[i] = networkUnsupported
	}
	d.networks[common.NetworkTCP6] = networkSupported
	d.healthy = true
	d.mu.Unlock()
	failed := checkResult{
		kind:   checkHealth,
		probes: []probeResult{{network: common.NetworkTCP6, err: errors.New("probe failed")}},
	}
	d.applyCheck(failed)
	d.applyCheck(failed)
	d.applyCheck(checkResult{
		kind:   checkHealth,
		probes: []probeResult{{network: common.NetworkTCP6, latency: time.Millisecond}},
	})
	logs := output.String()
	if got := strings.Count(logs, `"level":"warning"`); got != 1 {
		t.Fatalf("warning logs = %d, want 1\n%s", got, logs)
	}
	if got := strings.Count(logs, `"msg":"Connectivity recovered"`); got != 1 {
		t.Fatalf("recovery logs = %d, want 1\n%s", got, logs)
	}
	if got := strings.Count(logs, `"msg":"Connectivity probe failed"`); got != 2 {
		t.Fatalf("failed probe debug logs = %d, want 2\n%s", got, logs)
	}
}

func TestStaleCheckCannotUpdateNewSession(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	old := transport.Snapshot()
	result := checkResult{
		kind:   checkHealth,
		seq:    old.Seq,
		probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}},
	}
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("lost"))
	d.applySessionState(transport.Snapshot())
	transport.state.Transition(netproxy.SessionConnected, nil)
	if _, accepted := d.applyCheck(result); accepted {
		t.Fatal("stale result was accepted")
	}
	if d.RuntimeStatus().Healthy {
		t.Fatal("stale result recovered the new session")
	}
}

func TestSessionLossInvalidatesHealthImmediately(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	snapshot := transport.Snapshot()
	d.mu.Lock()
	d.healthy = true
	d.healthSeq = snapshot.Seq
	d.networks[0] = networkSupported
	d.mu.Unlock()
	if !d.RuntimeStatus().Healthy {
		t.Fatal("prepared dialer is not healthy")
	}
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("lost"))
	if !d.applySessionState(transport.Snapshot()) {
		t.Fatal("session transition was not applied")
	}
	if d.RuntimeStatus().Healthy || d.Usable(common.NetworkTCP4.NetworkType()) {
		t.Fatal("session loss left the dialer usable")
	}
}

func TestInitialSessionTransitionsDoNotNotifyGroup(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	d := newTestDialer(t, transport)
	group := d.group.observer.(*testGroup)

	d.applySessionState(transport.Snapshot())
	transport.state.Transition(netproxy.SessionConnecting, nil)
	d.applySessionState(transport.Snapshot())
	transport.state.Transition(netproxy.SessionConnected, nil)
	d.applySessionState(transport.Snapshot())
	if got := group.changes.Load(); got != 0 {
		t.Fatalf("group changes = %d, want no notification before the first check result", got)
	}
}

func TestDataPlaneFailureIsConfirmedFromReportTime(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{
		d.StatsKey(): {Subtag: d.Property.SubscriptionTag, Name: d.Name},
	}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	d.applyCheck(checkResult{
		kind:   checkInitial,
		probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}},
	})
	group := d.group.observer.(*testGroup)
	changesBeforeReport := group.changes.Load()
	d.ReportDataPlaneFailure()
	firstReport := d.failureReportedAt
	if firstReport.IsZero() || !d.RuntimeStatus().ConfirmingFailure {
		t.Fatal("data-plane failure did not enter confirmation")
	}
	if got := group.changes.Load(); got != changesBeforeReport+1 {
		t.Fatalf("group changes after first report = %d, want %d", got, changesBeforeReport+1)
	}
	d.ReportDataPlaneFailure()
	if !d.failureReportedAt.Equal(firstReport) {
		t.Fatal("repeated report replaced the first failure time")
	}
	if got := group.changes.Load(); got != changesBeforeReport+1 {
		t.Fatalf("repeated report notified group: changes = %d, want %d", got, changesBeforeReport+1)
	}
	d.applyCheck(checkResult{
		kind:   checkHealth,
		probes: []probeResult{{network: common.NetworkTCP4, err: errors.New("probe failed")}},
	})
	status := d.RuntimeStatus()
	if status.Healthy || status.ConfirmingFailure {
		t.Fatalf("confirmed failure status = %+v", status)
	}
	if got := stats.DefaultStore.GetNode(d.StatsKey()).LastFailureStartedAt; got.Unix() != firstReport.Unix() {
		t.Fatalf("failure started at %v, want %v", got, firstReport)
	}
}
