/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type testTransport struct{}

func (testTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (testTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type testSessionTransport struct {
	state *netproxy.StateBroadcaster
}

func newTestSessionTransport(state netproxy.SessionState) *testSessionTransport {
	return &testSessionTransport{state: netproxy.NewStateBroadcaster(state)}
}

func (d *testSessionTransport) Connect(context.Context) error {
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
	changes atomic.Int32
}

func (g *testGroup) DialerChanged(*Dialer) { g.changes.Add(1) }

var testDialerSequence atomic.Uint64

func newTestDialer(t *testing.T, transport netproxy.Dialer) *Dialer {
	t.Helper()
	id := testDialerSequence.Add(1)
	d := NewDialer(netproxy.NewRuntime(transport), &GlobalOption{
		CheckInterval:    time.Hour,
		CheckIntervalMax: time.Hour,
	}, &Property{Property: D.Property{
		Name: t.Name(),
		Link: fmt.Sprintf("test://%s/%d", t.Name(), id),
	}}, InitialCheckBlocking, "")
	d.RegisterDialerGroup(new(testGroup), 0.5, time.Minute)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func checkOptions(probes [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error)) []*checkOption {
	options := make([]*checkOption, common.NetworkTypeCount)
	for i := range options {
		options[i] = &checkOption{networkType: common.NetworkIndex(i).NetworkType(), probe: probes[i]}
	}
	return options
}

func TestStatsKeyEncodingSeparatesIdentityAndScope(t *testing.T) {
	left := makeStatsKey(&Property{SubscriptionTag: "sub", Property: D.Property{Link: "a\x1fb"}}, "c")
	right := makeStatsKey(&Property{SubscriptionTag: "sub", Property: D.Property{Link: "a"}}, "b\x1fc")
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
	d := NewDialer(netproxy.NewRuntime(testTransport{}), &GlobalOption{}, &Property{Property: D.Property{
		Name: t.Name(),
		Link: fmt.Sprintf("test://%s/%d", t.Name(), id),
	}}, InitialCheckDisabled, "")
	t.Cleanup(func() { _ = d.Close() })
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{
		d.StatsKey(): {Subtag: d.Property.SubscriptionTag, Name: d.Name},
	}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	if availability := stats.DefaultStore.GetNode(d.StatsKey()); availability.Seen {
		t.Fatalf("candidate dialer published availability: %+v", availability)
	}

	d.ActivateCheck(new(sync.WaitGroup))
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
	checker := newConnectivityChecker(d, checkOptions(probes))
	result := checker.perform(context.Background(), checkInitial, -1)
	applied := d.applyCheck(result)
	if !applied.accepted || !applied.success || !applied.initialDone || applied.primary != 0 {
		t.Fatalf("initial result = %+v", applied)
	}
	want := [common.NetworkTypeCount]NetworkSupportState{
		NetworkSupportConfirmed,
		NetworkSupportUnknown,
		NetworkSupportUnsupported,
		NetworkSupportUnknown,
	}
	if got := d.RuntimeStatus().SupportState; got != want {
		t.Fatalf("support = %v, want %v", got, want)
	}
}

func TestHealthCheckConfirmsFailureAndUsesAlternative(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.mu.Lock()
	d.healthy = true
	d.networks[0] = networkUsable
	d.networks[1] = networkUsable
	d.mu.Unlock()
	var primaryCalls, alternativeCalls atomic.Int32
	probes := [common.NetworkTypeCount]func(context.Context, *common.NetworkType) (bool, error){
		func(context.Context, *common.NetworkType) (bool, error) {
			primaryCalls.Add(1)
			return false, errors.New("primary failed")
		},
		func(context.Context, *common.NetworkType) (bool, error) {
			alternativeCalls.Add(1)
			return true, nil
		},
	}
	checker := newConnectivityChecker(d, checkOptions(probes))
	result := checker.perform(context.Background(), checkHealth, 0)
	applied := d.applyCheck(result)
	if !applied.success || applied.primary != 1 {
		t.Fatalf("health result = %+v", applied)
	}
	if got := primaryCalls.Load(); got != 2 {
		t.Fatalf("primary probes = %d, want 2", got)
	}
	if got := alternativeCalls.Load(); got != 1 {
		t.Fatalf("alternative probes = %d, want 1", got)
	}
	if d.SelectionSnapshot(common.NetworkTCP4.NetworkType()).Usable {
		t.Fatal("failed primary mode remained usable")
	}
	if !d.SelectionSnapshot(common.NetworkTCP6.NetworkType()).Usable {
		t.Fatal("successful alternative mode was not usable")
	}
}

func TestStaleCheckCannotUpdateNewSession(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	old := transport.Snapshot()
	option := &checkOption{
		networkType: common.NetworkTCP4.NetworkType(),
		probe:       func(context.Context, *common.NetworkType) (bool, error) { return true, nil },
	}
	result := checkResult{
		kind:    checkHealth,
		primary: 0,
		seq:     old.Seq,
		probes:  []probeResult{{option: option, ok: true, latency: time.Millisecond}},
	}
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("lost"))
	d.applySessionState(transport.Snapshot())
	transport.state.Transition(netproxy.SessionConnected, nil)
	if applied := d.applyCheck(result); applied.accepted {
		t.Fatalf("stale result was accepted: %+v", applied)
	}
	if d.Healthy() {
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
	d.networks[0] = networkUsable
	d.mu.Unlock()
	if !d.Healthy() {
		t.Fatal("prepared dialer is not healthy")
	}
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("lost"))
	if !d.applySessionState(transport.Snapshot()) {
		t.Fatal("session transition was not applied")
	}
	if d.Healthy() || d.Usable(common.NetworkTCP4.NetworkType()) {
		t.Fatal("session loss left the dialer usable")
	}
}

func TestInitialSessionTransitionsDoNotNotifyGroup(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	d := newTestDialer(t, transport)
	group := d.group.group.(*testGroup)

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
	option := &checkOption{
		networkType: common.NetworkTCP4.NetworkType(),
		probe:       func(context.Context, *common.NetworkType) (bool, error) { return true, nil },
	}
	d.applyCheck(checkResult{
		kind:   checkInitial,
		probes: []probeResult{{option: option, ok: true, latency: time.Millisecond}},
	})
	group := d.group.group.(*testGroup)
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
		probes: []probeResult{{option: option, err: errors.New("probe failed")}},
	})
	status := d.RuntimeStatus()
	if status.Healthy || status.ConfirmingFailure {
		t.Fatalf("confirmed failure status = %+v", status)
	}
	if got := stats.DefaultStore.GetNode(d.StatsKey()).LastFailureStartedAt; got.Unix() != firstReport.Unix() {
		t.Fatalf("failure started at %v, want %v", got, firstReport)
	}
}
