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
	state      *netproxy.StateBroadcaster
	connects   atomic.Int32
	connectErr error
}

func newTestSessionTransport(state netproxy.SessionState) *testSessionTransport {
	return &testSessionTransport{state: netproxy.NewStateBroadcaster(state)}
}

func (d *testSessionTransport) Connect(context.Context) error {
	d.connects.Add(1)
	d.state.Transition(netproxy.SessionConnecting, nil)
	if d.connectErr != nil {
		d.state.Transition(netproxy.SessionDisconnected, d.connectErr)
		return d.connectErr
	}
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
	if session, ok := transport.(interface {
		netproxy.Session
		io.Closer
	}); ok {
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
	}, true, "")
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

func performCheck(c *connectivityChecker, ctx context.Context, kind checkKind) checkResult {
	c.d.mu.RLock()
	attempt := checkAttempt{
		kind:       kind,
		generation: c.d.failureGeneration,
	}
	c.d.mu.RUnlock()
	return c.performAttempt(ctx, attempt)
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
	}, false, "")
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
	if d.RuntimeStatus().InitialCheckDone {
		t.Fatal("new dialer reports a completed initial check")
	}
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
	result := performCheck(checker, context.Background(), checkInitial)
	applied, accepted := d.applyCheck(result)
	if !accepted || !applied.success {
		t.Fatalf("initial result = %+v", applied)
	}
	want := [common.NetworkTypeCount]NetworkSupportState{
		NetworkSupportConfirmed,
		NetworkSupportUnknown,
		NetworkSupportUnsupported,
		NetworkSupportUnknown,
	}
	status := d.RuntimeStatus()
	if !status.InitialCheckDone {
		t.Fatal("completed initial result was not retained by the dialer")
	}
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

func TestUnsupportedInitialCheckIsComplete(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	var probes [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error)
	for i := range probes {
		probes[i] = func(context.Context, *common.NetworkType) (bool, error) {
			return false, netproxy.UnsupportedTunnelTypeError
		}
	}
	checker := newConnectivityChecker(d, checkProbe(probes))
	result := performCheck(checker, context.Background(), checkInitial)
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
	logger.SetLevel(log.TraceLevel)
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
			if index == common.NetworkTCP6 || index == common.NetworkTCP4 {
				return true, nil
			}
			return false, errors.New("probe failed")
		}
	}
	checker := newConnectivityChecker(d, checkProbe(probes))
	result := performCheck(checker, context.Background(), checkInitial)
	if _, accepted := d.applyCheck(result); !accepted {
		t.Fatal("initial result was rejected")
	}
	logs := output.String()
	if got := strings.Count(logs, `"msg":"Connectivity initial check`); got != common.NetworkTypeCount {
		t.Fatalf("initial result logs = %d, want %d\n%s", got, common.NetworkTypeCount, logs)
	}
	if got := strings.Count(logs, `"msg":"Connectivity modes supported"`); got != 1 {
		t.Fatalf("support discovery logs = %d, want 1\n%s", got, logs)
	}
	if !strings.Contains(logs, `"networks":["tcp6","tcp4"]`) {
		t.Fatalf("initial supported modes were not combined into one network list:\n%s", logs)
	}
}

func TestSupportRetryLogsTransitionsTogether(t *testing.T) {
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
		d.networks[i] = networkUnknown
	}
	d.health = healthUnhealthy
	d.mu.Unlock()
	result := checkResult{
		kind: checkSupport,
		probes: []probeResult{
			{network: common.NetworkTCP6},
			{network: common.NetworkTCP4},
			{network: common.NetworkUDP6, err: netproxy.UnsupportedTunnelTypeError},
			{network: common.NetworkUDP4, err: netproxy.UnsupportedTunnelTypeError},
		},
	}
	if _, accepted := d.applyCheck(result); !accepted {
		t.Fatal("support result was rejected")
	}
	logs := output.String()
	for _, want := range []string{
		`"msg":"Connectivity modes supported","networks":["tcp6","tcp4"]`,
		`"msg":"Connectivity modes unsupported","networks":["udp6","udp4"]`,
		`"msg":"Connectivity recovered"`,
	} {
		if got := strings.Count(logs, want); got != 1 {
			t.Fatalf("log %s count = %d, want 1\n%s", want, got, logs)
		}
	}
	output.Reset()
	if _, accepted := d.applyCheck(result); !accepted {
		t.Fatal("unchanged support result was rejected")
	}
	if output.Len() != 0 {
		t.Fatalf("unchanged support results were logged again:\n%s", output.String())
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
	go func() { resultCh <- performCheck(checker, context.Background(), checkInitial) }()
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
		4 * time.Second,
		16 * time.Second,
		time.Minute + 4*time.Second,
		4*time.Minute + 16*time.Second,
		17*time.Minute + 4*time.Second,
		time.Hour,
		time.Hour,
	}
	for i, expected := range want {
		interval = nextRetryInterval(interval, time.Hour)
		if interval != expected {
			t.Fatalf("retry interval %d = %v, want %v", i, interval, expected)
		}
	}
	if got := initialRetryInterval(time.Hour); got != time.Second {
		t.Fatalf("initial interval = %v, want 1s", got)
	}
	if got := initialRetryInterval(time.Second); got != time.Second {
		t.Fatalf("capped initial interval = %v, want 1s", got)
	}
	if low, high := retryJitterRange(time.Hour, time.Hour); low != 48*time.Minute || high != time.Hour {
		t.Fatalf("capped jitter range = [%v, %v], want [48m, 1h]", low, high)
	}
	if got := jitterCheckInterval(10 * time.Second); got < 8*time.Second || got > 12*time.Second {
		t.Fatalf("jittered interval = %v, want [8s, 12s]", got)
	}
	if got := jitterRetryInterval(time.Hour, time.Hour); got < 48*time.Minute || got > time.Hour {
		t.Fatalf("capped jittered interval = %v, want [48m, 1h]", got)
	}
}

func TestHealthRetryBackoff(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.CheckInterval = 3 * time.Minute
	d.CheckIntervalMax = time.Hour
	checker := newConnectivityChecker(d, nil)
	t.Cleanup(func() {
		checker.stopRetries()
	})

	want := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
	}
	for i, expected := range want {
		checker.updateHealthSchedule(false)
		if checker.healthInterval != expected {
			t.Fatalf("health retry interval %d = %v, want %v", i, checker.healthInterval, expected)
		}
	}
	checker.updateHealthSchedule(true)
	if checker.healthInterval != d.CheckInterval || checker.backingOff {
		t.Fatalf("health recovery interval = %v, backingOff=%v", checker.healthInterval, checker.backingOff)
	}
}

func TestExplicitRequestResetsSupportRetryWithoutCanonicalMode(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	for i := range d.networks {
		d.networks[i] = networkUnknown
	}
	d.mu.Unlock()
	probed := make(chan struct{}, 1)
	release := make(chan struct{})
	checker := newConnectivityChecker(d, func(ctx context.Context, _ *common.NetworkType) (bool, error) {
		select {
		case probed <- struct{}{}:
		default:
		}
		select {
		case <-release:
			return false, errors.New("still unsupported")
		case <-ctx.Done():
			return false, ctx.Err()
		}
	})
	t.Cleanup(func() {
		checker.stopRetries()
	})
	checker.retryInterval = time.Hour
	checker.scheduleSupport()
	d.RequestConnectivityCheck()
	checker.start(checker.requestedCheckKind())
	if checker.retryInterval != supportRetryInitialInterval || !checker.supportAt.IsZero() || checker.runningKind != checkSupport {
		t.Fatalf("support retry after request = %v, scheduled=%v, kind=%v", checker.retryInterval, !checker.supportAt.IsZero(), checker.runningKind)
	}
	if d.connectivityCheckRequested() {
		t.Fatal("explicit connectivity request was not consumed")
	}
	select {
	case <-probed:
	case <-time.After(time.Second):
		t.Fatal("explicit request did not start support checking immediately")
	}
	close(release)
	if !finishCheck(checker, <-checker.results) {
		t.Fatal("checker stopped after requested support check")
	}
	if checker.retryInterval != 4*time.Second || checker.supportAt.IsZero() {
		t.Fatalf("support retry after failed check = %v, scheduled=%v", checker.retryInterval, !checker.supportAt.IsZero())
	}
}

func TestSupportDiscoveryUsesNewCanonicalResult(t *testing.T) {
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
	d.networks[common.NetworkTCP6] = networkUnknown
	d.networks[common.NetworkTCP4] = networkSupported
	d.health = healthUnhealthy
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
	if !accepted || !applied.success || !applied.healthApplied {
		t.Fatalf("support discovery = %+v, accepted=%v", applied, accepted)
	}
	if got := group.forces.Load(); got != 1 {
		t.Fatalf("support discovery forced refreshes = %d, want 1", got)
	}
	if got := SelectionForceMask(group.forceMask.Load()); got != SelectionForceFor(common.NetworkTCP6) {
		t.Fatalf("support discovery force mask = %04b, want tcp6", got)
	}
	if got := strings.Count(output.String(), `"msg":"Connectivity modes supported"`); got != 1 {
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
		checker.stopRetries()
	})
	checker.healthAt = time.Now()
	checker.updateSchedule(checkSupport, applied)
	if !checker.healthAt.IsZero() && !checker.healthAt.After(time.Now()) {
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
	if got := strings.Count(output.String(), `"msg":"Connectivity modes supported"`); got != 1 {
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
	d.health = healthHealthy
	d.mu.Unlock()
	checker := newConnectivityChecker(d, nil)
	t.Cleanup(func() {
		checker.stopRetries()
	})
	if !checker.supportPending() {
		t.Fatal("unknown mode was not pending while another mode was supported")
	}
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
	d.health = healthUnhealthy
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
		checker.stopRetries()
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
	healthResult := performCheck(checker, context.Background(), checkHealth)
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
	d.health = healthHealthy
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
	result := performCheck(checker, context.Background(), checkHealth)
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
	checker := newConnectivityChecker(d, checkProbe(probes))
	result := performCheck(checker, context.Background(), checkSupport)
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
	d.health = healthHealthy
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
	logger.SetLevel(log.InfoLevel)
	output.Reset()
	d.applyCheck(checkResult{kind: checkHealth, probes: []probeResult{{network: common.NetworkTCP6}}})
	if output.Len() != 0 {
		t.Fatalf("unchanged healthy state was logged at info level:\n%s", output.String())
	}
}

func TestSessionLoggingDistinguishesFailureFromLocalCleanup(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput, previousLevel := logger.Out, logger.Level
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() { logger.SetOutput(previousOutput); logger.SetLevel(previousLevel) })
	for _, tc := range []struct {
		name        string
		cause       error
		wantWarning bool
	}{
		{"local cleanup", netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Origin: netproxy.OriginLocalCleanup}), false},
		{"planned reconnect", nil, false},
		{"carrier failure", errors.New("connection reset by peer"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := newTestSessionTransport(netproxy.SessionConnected)
			d := newTestDialer(t, transport)
			prepareRecoveryDialer(d)
			transport.state.Transition(netproxy.SessionDisconnected, tc.cause)
			output.Reset()
			d.applySessionState(transport.Snapshot())
			d.applySessionState(transport.Snapshot())
			count := strings.Count(output.String(), "Outbound session unavailable")
			if count != 0 && !tc.wantWarning || count != 1 && tc.wantWarning {
				t.Fatalf("session warning count = %d, want warning %v: %s", count, tc.wantWarning, output.String())
			}
		})
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
	d.health = healthHealthy
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

func TestSessionLossImmediatelyRetriesAndRecordsConnectFailure(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	transport.connectErr = errors.New("reconnect failed")
	d := newTestDialer(t, transport)
	initial := transport.Snapshot()
	d.mu.Lock()
	d.health = healthHealthy
	d.healthSeq = initial.Seq
	for i := range d.networks {
		d.networks[i] = networkUnsupported
	}
	d.networks[common.NetworkTCP4] = networkSupported
	d.mu.Unlock()
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{
		d.StatsKey(): {Name: d.Name},
	}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })

	checker := newConnectivityChecker(d, func(context.Context, *common.NetworkType) (bool, error) {
		return true, nil
	})
	checker.backingOff = true
	checker.healthInterval = time.Minute
	t.Cleanup(func() {
		checker.stopRetries()
	})
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("session lost"))
	checker.handleSessionEvent(transport.Snapshot())

	checker.dispatch()

	var result checkResult
	select {
	case result = <-checker.results:
	case <-time.After(time.Second):
		t.Fatal("session loss did not trigger an immediate connectivity check")
	}
	if !finishCheck(checker, result) {
		t.Fatal("connectivity checker stopped after reconnect failure")
	}
	if got := transport.connects.Load(); got != 1 {
		t.Fatalf("immediate reconnect attempts = %d, want 1", got)
	}
	if checker.healthInterval != time.Second {
		t.Fatalf("session-triggered retry interval = %v, want 1s", checker.healthInterval)
	}
	availability := stats.DefaultStore.GetNode(d.StatsKey())
	if availability.LastCheckAt.IsZero() || availability.ChecksTotal != 1 || availability.ChecksFailed != 1 {
		t.Fatalf("reconnect failure availability = %+v", availability)
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
	d.ReportDataPlaneError(errors.New("upstream relay failed"))
	firstReport := d.failureReportedAt
	if firstReport.IsZero() || !d.RuntimeStatus().ConfirmingFailure {
		t.Fatal("data-plane failure did not enter confirmation")
	}
	if got := group.changes.Load(); got != changesBeforeReport+1 {
		t.Fatalf("group changes after first report = %d, want %d", got, changesBeforeReport+1)
	}
	d.ReportDataPlaneError(errors.New("upstream relay failed"))
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
	generation := d.failureGeneration
	d.ReportDataPlaneError(errors.New("upstream relay failed"))
	if d.connectivityCheckRequested() || d.failureGeneration != generation {
		t.Fatal("data-plane failure requested another check while the node was already unhealthy")
	}
}

func TestCheckStartedBeforeDataPlaneFailureCannotClearConfirmation(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.applyCheck(checkResult{
		kind:   checkInitial,
		probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}},
	})
	attempt := d.beginConnectivityCheck(checkHealth)
	d.ReportDataPlaneError(errors.New("upstream relay failed"))

	if _, accepted := d.applyCheck(checkResult{
		kind:       attempt.kind,
		generation: attempt.generation,
		probes:     []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}},
	}); !accepted {
		t.Fatal("pre-failure check was rejected instead of retained as an older observation")
	}
	if status := d.RuntimeStatus(); !status.Healthy || !status.ConfirmingFailure {
		t.Fatalf("pre-failure success cleared confirmation: %+v", status)
	}
	if !d.connectivityCheckRequested() {
		t.Fatal("failure arriving during a check did not leave a follow-up pending")
	}

	followUp := d.beginConnectivityCheck(checkHealth)
	if followUp.reasons != checkRequestDataPlane || followUp.generation <= attempt.generation {
		t.Fatalf("follow-up attempt = %+v, previous = %+v", followUp, attempt)
	}
	d.applyCheck(checkResult{
		kind:       followUp.kind,
		generation: followUp.generation,
		probes:     []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}},
	})
	if status := d.RuntimeStatus(); !status.Healthy || status.ConfirmingFailure {
		t.Fatalf("covering success did not clear confirmation: %+v", status)
	}
}

func TestEnvironmentChangeRejectsOlderCheck(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	attempt := d.beginConnectivityCheck(checkInitial)
	d.RequestConnectivityCheck()
	if _, accepted := d.applyCheck(checkResult{
		kind:       attempt.kind,
		generation: attempt.generation,
		probes:     []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}},
	}); accepted {
		t.Fatal("check from the previous environment was accepted")
	}
	if !d.connectivityCheckRequested() {
		t.Fatal("environment recheck was lost with the stale result")
	}
}

func TestDataPlaneRequestDoesNotResetSupportBackoff(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	checker := newConnectivityChecker(d, nil)
	t.Cleanup(func() {
		checker.stopRetries()
	})
	checker.retryInterval = time.Hour
	checker.supportAt = time.Now().Add(time.Hour)
	checker.backingOff = true
	checker.healthInterval = time.Minute

	checker.resetForRequest(checkRequestDataPlane)
	if checker.retryInterval != time.Hour || checker.supportAt.IsZero() {
		t.Fatalf("data-plane request reset support retry: interval=%v scheduled=%v", checker.retryInterval, !checker.supportAt.IsZero())
	}
	if checker.backingOff || checker.healthInterval != d.CheckInterval {
		t.Fatalf("data-plane request did not reset health retry: interval=%v backingOff=%v", checker.healthInterval, checker.backingOff)
	}
}

func TestCanceledCheckDNSResolutionReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := parseCheckDNSOption(ctx, []string{"cancel.invalid:53"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled DNS option resolution error = %v", err)
	}
}

func TestConnectivityProbeConcurrencyIsLimited(t *testing.T) {
	previousSlots := connectivityCheckSlots
	connectivityCheckSlots = make(chan struct{}, 2)
	t.Cleanup(func() { connectivityCheckSlots = previousSlots })

	d := newTestDialer(t, testTransport{})
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	checker := newConnectivityChecker(d, func(context.Context, *common.NetworkType) (bool, error) {
		entered <- struct{}{}
		<-release
		return true, nil
	})
	t.Cleanup(func() {
		checker.stopRetries()
	})
	done := make(chan struct{}, 4)
	for range 4 {
		go func() {
			checker.runProbe(context.Background(), common.NetworkTCP4)
			done <- struct{}{}
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("probe did not acquire available capacity")
		}
	}
	select {
	case <-entered:
		t.Fatal("probe concurrency exceeded the configured capacity")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	for range 4 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("limited probe did not finish")
		}
	}
}
