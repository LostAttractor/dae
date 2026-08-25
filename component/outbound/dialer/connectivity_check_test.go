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
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type blockingFailConnectDialer struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (d *blockingFailConnectDialer) Alive() bool { return false }

func (d *blockingFailConnectDialer) Connect() error {
	if d.calls.Add(1) == 1 {
		close(d.started)
	}
	<-d.release
	return errors.New("connect failed")
}

func (d *blockingFailConnectDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (d *blockingFailConnectDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type failOnceConnectDialer struct {
	calls atomic.Int32
}

func (d *failOnceConnectDialer) Alive() bool { return true }

func (d *failOnceConnectDialer) Connect() error {
	if d.calls.Add(1) == 1 {
		return errors.New("connect failed")
	}
	return nil
}

func (d *failOnceConnectDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (d *failOnceConnectDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type connectedTestDialer struct{}

func (connectedTestDialer) Alive() bool    { return true }
func (connectedTestDialer) Connect() error { return nil }
func (connectedTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (connectedTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type statefulTestDialer struct {
	alive      atomic.Bool
	connects   atomic.Int32
	connectErr error
}

type serializedConnectTestDialer struct {
	alive   atomic.Bool
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (d *serializedConnectTestDialer) Alive() bool { return d.alive.Load() }
func (d *serializedConnectTestDialer) Connect() error {
	if d.calls.Add(1) != 1 {
		return errors.New("concurrent Connect replaced the new session")
	}
	close(d.started)
	<-d.release
	d.alive.Store(true)
	return nil
}
func (d *serializedConnectTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (d *serializedConnectTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (d *statefulTestDialer) Alive() bool { return d.alive.Load() }
func (d *statefulTestDialer) Connect() error {
	d.connects.Add(1)
	if d.connectErr == nil {
		d.alive.Store(true)
	}
	return d.connectErr
}
func (d *statefulTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (d *statefulTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type statusRecordingGroup struct {
	notified chan stats.Availability
}

var testDialerSequence atomic.Uint64

func (g *statusRecordingGroup) NotifyStatusChange(d *Dialer) {
	select {
	case g.notified <- stats.GetNode(d.StatsKey()):
	default:
	}
}

func (g *statusRecordingGroup) GetEmaAlpha() float64 { return 0.5 }

func (g *statusRecordingGroup) GetTimeoutPenalty() time.Duration { return time.Minute }

func newTestDialer(t *testing.T, transport netproxy.Dialer) *Dialer {
	t.Helper()
	id := testDialerSequence.Add(1)
	return NewDialer(transport, &GlobalOption{}, &Property{Property: D.Property{
		Name: t.Name(),
		Link: fmt.Sprintf("test://%s/%d", t.Name(), id),
	}}, true)
}

func TestScopedDialersSerializeSharedTransportConnect(t *testing.T) {
	transport := &serializedConnectTestDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	base := newTestDialer(t, transport)
	clone := base.CloneForStatsScope("override-group")
	t.Cleanup(func() {
		_ = base.Close()
		_ = clone.Close()
	})
	if base.connectMu != clone.connectMu {
		t.Fatal("scoped dialers do not share their transport connection lock")
	}

	baseResult := make(chan error, 1)
	cloneResult := make(chan error, 1)
	go func() { baseResult <- base.ensureConnected() }()
	<-transport.started
	go func() { cloneResult <- clone.ensureConnected() }()

	select {
	case err := <-cloneResult:
		t.Fatalf("clone Connect completed before the in-flight shared Connect: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(transport.release)
	if err := <-baseResult; err != nil {
		t.Fatal(err)
	}
	if err := <-cloneResult; err != nil {
		t.Fatal(err)
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("shared transport Connect calls = %d, want 1", got)
	}
}

func TestCapabilityCheckOnlyClassifiesUnknownModes(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })

	checkErrs := [4]error{
		nil,
		context.DeadlineExceeded,
		fmt.Errorf("wrapped: %w", netproxy.UnsupportedTunnelTypeError),
		errors.New("network is unreachable"),
	}
	checkOK := [4]bool{true, false, false, false}
	var calls [4]atomic.Int32
	checkOpts := make([]*checkOption, 4)
	for i := range checkOpts {
		i := i
		checkOpts[i] = &checkOption{
			networkType: common.IndexToNetworkType(i),
			probe: func(context.Context, *common.NetworkType) (bool, error) {
				calls[i].Add(1)
				return checkOK[i], checkErrs[i]
			},
		}
	}

	if best, _ := d.checkCapabilities(checkOpts, capabilityCheckInitial); best != checkOpts[0] {
		t.Fatalf("best check option = %p, want %p", best, checkOpts[0])
	}
	want := [4]NetworkSupportState{
		NetworkSupportConfirmed,
		NetworkSupportUnknown,
		NetworkSupportUnsupported,
		NetworkSupportUnknown,
	}
	for i, state := range want {
		networkType := common.IndexToNetworkType(i)
		if got := d.SupportState(networkType); got != state {
			t.Errorf("support[%s] = %s, want %s", networkType, got, state)
		}
		if got := d.ConfirmedSupport(networkType); got != (state == NetworkSupportConfirmed) {
			t.Errorf("ConfirmedSupport(%s) = %v for state %s", networkType, got, state)
		}
	}

	// Terminal states are skipped. Only the still-unknown modes are checked.
	checkOK[0] = false
	checkErrs[0] = context.DeadlineExceeded
	checkOK[1] = true
	checkErrs[1] = nil
	checkOK[2] = true
	checkErrs[2] = nil
	if best, _ := d.checkCapabilities(checkOpts, capabilityCheckRuntime); best != checkOpts[1] {
		t.Fatalf("rediscovered check option = %p, want %p", best, checkOpts[1])
	}
	want = [4]NetworkSupportState{
		NetworkSupportConfirmed,
		NetworkSupportConfirmed,
		NetworkSupportUnsupported,
		NetworkSupportUnknown,
	}
	for i, state := range want {
		if got := d.SupportState(checkOpts[i].networkType); got != state {
			t.Errorf("support[%s] = %s, want %s", checkOpts[i].networkType, got, state)
		}
	}
	wantCalls := [4]int32{1, 2, 1, 2}
	for i, want := range wantCalls {
		if got := calls[i].Load(); got != want {
			t.Errorf("checks[%s] = %d, want %d", checkOpts[i].networkType, got, want)
		}
	}

	// Resolve the last unknown mode, then verify that another capability check is a
	// no-op and cannot change either terminal state.
	checkErrs[3] = fmt.Errorf("wrapped: %w", netproxy.UnsupportedTunnelTypeError)
	if _, changed := d.checkCapabilities(checkOpts, capabilityCheckRuntime); !changed {
		t.Fatal("resolving the last unknown mode reported no state change")
	}
	if got := d.SupportState(checkOpts[3].networkType); got != NetworkSupportUnsupported {
		t.Fatalf("last unknown support = %s, want unsupported", got)
	}
	if _, changed := d.checkCapabilities(checkOpts, capabilityCheckRuntime); changed {
		t.Fatal("terminal capability check reported a state change")
	}
	wantCalls = [4]int32{1, 2, 1, 3}
	for i, want := range wantCalls {
		if got := calls[i].Load(); got != want {
			t.Errorf("terminal checks[%s] = %d, want %d", checkOpts[i].networkType, got, want)
		}
	}
	if !d.Alive() {
		t.Fatal("capability rediscovery failure changed node-level health")
	}
}

func TestCapabilityCheckProbesDuplicateNetworkOnce(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })

	var calls atomic.Int32
	checkOpt := &checkOption{
		networkType: common.IndexToNetworkType(0),
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			calls.Add(1)
			return true, nil
		},
	}
	best, changed := d.checkCapabilities(
		[]*checkOption{checkOpt, checkOpt}, capabilityCheckRuntime,
	)
	if best != checkOpt || !changed {
		t.Fatalf("capability result = %p, %v; want %p, true", best, changed, checkOpt)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("duplicate network probes = %d, want 1", got)
	}
}

func TestCapabilityScheduleOnlyTracksConfiguredNetworks(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })
	checkOpt := &checkOption{networkType: common.IndexToNetworkType(0)}
	d.SetSupported(checkOpt.networkType, true)

	if d.hasPendingCapabilityCheck([]*checkOption{checkOpt}) {
		t.Fatal("unconfigured unknown networks kept capability discovery active")
	}
}

func TestRuntimeCapabilityCheckDoesNotReconnectNode(t *testing.T) {
	transport := &statefulTestDialer{connectErr: errors.New("connect failed")}
	d := newTestDialer(t, transport)
	t.Cleanup(func() { _ = d.Close() })
	var probes atomic.Int32
	checkOpt := &checkOption{
		networkType: common.IndexToNetworkType(0),
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			probes.Add(1)
			return false, errors.New("probe failed")
		},
	}

	if got, _ := d.checkCapabilities([]*checkOption{checkOpt}, capabilityCheckRuntime); got != nil {
		t.Fatalf("runtime capability check selected %p", got)
	}
	if got := transport.connects.Load(); got != 0 {
		t.Fatalf("runtime capability check connected %d times", got)
	}
	if got := probes.Load(); got != 0 {
		t.Fatalf("runtime capability check probed a disconnected node %d times", got)
	}
	if avail := stats.GetNode(d.StatsKey()); avail.Seen {
		t.Fatalf("runtime capability check changed node statistics: %+v", avail)
	}
	if ok, attempted := (&connectivityCheckLoop{d: d, options: []*checkOption{checkOpt}}).discoverCapabilities(); !ok || attempted {
		t.Fatalf("disconnected capability discovery = ok %v, attempted %v", ok, attempted)
	}
}

func TestRuntimeCapabilitySuccessDoesNotRecoverNode(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })
	checkOpt := &checkOption{
		networkType: common.IndexToNetworkType(0),
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			return true, nil
		},
	}

	if got, _ := d.checkCapabilities([]*checkOption{checkOpt}, capabilityCheckRuntime); got != checkOpt {
		t.Fatalf("runtime capability check = %p, want %p", got, checkOpt)
	}
	if got := d.SupportState(checkOpt.networkType); got != NetworkSupportConfirmed {
		t.Fatalf("runtime capability state = %s, want confirmed", got)
	}
	if d.Alive() {
		t.Fatal("runtime capability success recovered node health")
	}
	if avail := stats.GetNode(d.StatsKey()); avail.Seen {
		t.Fatalf("runtime capability success changed node statistics: %+v", avail)
	}
}

func TestInitialCheckWakesForConnectivityRecheck(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 4)}
	d.RegisterDialerGroup(group)
	t.Cleanup(func() { _ = d.Close() })

	var online atomic.Bool
	checkOpts := make([]*checkOption, 4)
	for i := range checkOpts {
		checkOpts[i] = &checkOption{
			networkType: common.IndexToNetworkType(i),
			probe: func(context.Context, *common.NetworkType) (bool, error) {
				if online.Load() {
					return true, nil
				}
				return false, context.DeadlineExceeded
			},
		}
	}

	result := make(chan *checkOption, 1)
	go func() { result <- d.runInitialCheck(checkOpts) }()
	select {
	case avail := <-group.notified:
		if avail.ChecksFailed != 1 {
			t.Fatalf("first check availability = %+v", avail)
		}
	case <-time.After(time.Second):
		t.Fatal("initial check did not publish its first failure")
	}

	online.Store(true)
	d.NotifyConnectivityRecheck()
	select {
	case opt := <-result:
		if opt == nil {
			t.Fatal("woken initial check did not recover")
		}
	case <-time.After(time.Second):
		t.Fatal("connectivity recheck did not interrupt initial backoff")
	}
}

func TestInitialCheckStopsWhenAllModesAreUnsupported(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })

	var calls [4]atomic.Int32
	checkOpts := make([]*checkOption, 4)
	for i := range checkOpts {
		i := i
		checkOpts[i] = &checkOption{
			networkType: common.IndexToNetworkType(i),
			probe: func(context.Context, *common.NetworkType) (bool, error) {
				calls[i].Add(1)
				return false, netproxy.UnsupportedTunnelTypeError
			},
		}
	}

	result := make(chan *checkOption, 1)
	go func() { result <- d.runInitialCheck(checkOpts) }()
	select {
	case opt := <-result:
		if opt != nil {
			t.Fatalf("unsupported modes selected check option %p", opt)
		}
	case <-time.After(time.Second):
		t.Fatal("initial capability discovery retried terminal states")
	}
	for i := range checkOpts {
		if got := d.SupportState(checkOpts[i].networkType); got != NetworkSupportUnsupported {
			t.Errorf("support[%d] = %s, want unsupported", i, got)
		}
		if got := calls[i].Load(); got != 1 {
			t.Errorf("checks[%d] = %d, want 1", i, got)
		}
	}
}

func TestConnectivityRecheckDoesNotProbeUnknownCapabilities(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour

	confirmedType := common.IndexToNetworkType(0)
	unknownType := common.IndexToNetworkType(1)
	d.SetSupported(confirmedType, true)
	d.Update(true, time.Millisecond, confirmedType, nil)
	healthChecked := make(chan struct{}, 1)
	confirmed := &checkOption{
		networkType: confirmedType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			healthChecked <- struct{}{}
			return true, nil
		},
	}
	var capabilityChecks atomic.Int32
	unknown := &checkOption{
		networkType: unknownType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			capabilityChecks.Add(1)
			return true, nil
		},
	}

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(confirmed, []*checkOption{confirmed, unknown})
	}()
	d.NotifyConnectivityRecheck()
	select {
	case <-healthChecked:
	case <-time.After(time.Second):
		t.Fatal("connectivity recheck did not run a health check")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if got := capabilityChecks.Load(); got != 0 {
		t.Fatalf("unknown capability checks = %d, want 0", got)
	}
	if got := d.SupportState(unknownType); got != NetworkSupportUnknown {
		t.Fatalf("unknown capability became %s", got)
	}
}

func TestConnectivityRecheckUsesConfirmedAlternative(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 4)}
	d.RegisterDialerGroup(group)

	primaryType := common.IndexToNetworkType(0)
	alternativeType := common.IndexToNetworkType(1)
	d.SetSupported(primaryType, true)
	d.SetSupported(alternativeType, true)
	d.Update(true, time.Millisecond, primaryType, nil)
	var primaryChecks atomic.Int32
	alternativeChecked := make(chan struct{}, 1)
	primary := &checkOption{
		networkType: primaryType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			primaryChecks.Add(1)
			return false, errors.New("primary path unavailable")
		},
	}
	alternative := &checkOption{
		networkType: alternativeType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			alternativeChecked <- struct{}{}
			return true, nil
		},
	}

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(primary, []*checkOption{primary, alternative})
	}()
	d.NotifyConnectivityRecheck()
	select {
	case <-alternativeChecked:
	case <-time.After(time.Second):
		t.Fatal("connectivity recheck did not try the confirmed alternative")
	}
	select {
	case <-group.notified:
	case <-time.After(time.Second):
		t.Fatal("connectivity recheck did not publish health")
	}
	d.NotifyConnectivityRecheck()
	select {
	case <-alternativeChecked:
	case <-time.After(time.Second):
		t.Fatal("subsequent recheck did not use the promoted alternative")
	}
	select {
	case <-group.notified:
	case <-time.After(time.Second):
		t.Fatal("subsequent connectivity recheck did not publish health")
	}
	time.Sleep(20 * time.Millisecond)
	if got := primaryChecks.Load(); got != 2 {
		t.Fatalf("local connectivity event retried remote mode %d times, want only the two health probes", got)
	}
	if alive, support := d.SelectionState(primaryType); alive || support != NetworkSupportConfirmed {
		t.Fatalf("primary state = alive %v, support %v", alive, support)
	}
	if alive, support := d.SelectionState(alternativeType); !alive || support != NetworkSupportConfirmed {
		t.Fatalf("alternative state = alive %v, support %v", alive, support)
	}
	if !d.Alive() {
		t.Fatal("working confirmed alternative did not preserve node health")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCapabilityCheckRecoversFailedConfirmedMode(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })
	networkType := common.IndexToNetworkType(0)
	d.SetSupported(networkType, true)
	d.Update(true, time.Millisecond, networkType, nil)
	d.setModeAlive(networkType, false)

	checkOpt := &checkOption{
		networkType: networkType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			return true, nil
		},
	}
	if !d.hasPendingModeRecovery([]*checkOption{checkOpt}) {
		t.Fatal("failed confirmed mode did not schedule recovery")
	}
	if changed := d.recoverModeHealth([]*checkOption{checkOpt}); !changed {
		t.Fatal("mode recovery reported no state change")
	}
	if alive, support := d.SelectionState(networkType); !alive || support != NetworkSupportConfirmed {
		t.Fatalf("recovered state = alive %v, support %v", alive, support)
	}
}

func TestHealthCheckHedgesSlowProbe(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })
	started := make(chan struct{})
	canceled := make(chan struct{})
	var calls atomic.Int32
	option := &checkOption{
		networkType: common.IndexToNetworkType(0),
		probe: func(ctx context.Context, _ *common.NetworkType) (bool, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-ctx.Done()
				close(canceled)
				return false, ctx.Err()
			}
			return true, nil
		},
	}
	loop := &connectivityCheckLoop{d: d, lastLatency: time.Millisecond}
	begin := time.Now()
	result := loop.checkHealthOption(option)
	if !result.ok {
		t.Fatalf("hedged health check failed: %v", result.err)
	}
	if elapsed := time.Since(begin); elapsed < healthCheckHedgeMinDelay || elapsed > time.Second {
		t.Fatalf("hedged health check took %v", elapsed)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("primary probe did not start")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("winning hedge did not cancel the primary probe")
	}
}

func TestHealthCheckDoesNotHedgeFastSuccess(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })
	var calls atomic.Int32
	option := &checkOption{
		networkType: common.IndexToNetworkType(0),
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			calls.Add(1)
			return true, nil
		},
	}

	if result := (&connectivityCheckLoop{d: d}).checkHealthOption(option); !result.ok {
		t.Fatalf("health check failed: %v", result.err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("health probes = %d, want 1", got)
	}
}

func TestHealthCheckTriesDuplicateNetworkOnce(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	t.Cleanup(func() { _ = d.Close() })
	primaryType := common.IndexToNetworkType(0)
	alternativeType := common.IndexToNetworkType(1)
	d.SetSupported(primaryType, true)
	d.SetSupported(alternativeType, true)
	var primaryChecks atomic.Int32
	primary := &checkOption{
		networkType: primaryType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			primaryChecks.Add(1)
			return false, errors.New("primary failed")
		},
	}
	duplicate := &checkOption{networkType: primaryType, probe: primary.probe}
	alternative := &checkOption{
		networkType: alternativeType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			return true, nil
		},
	}
	loop := &connectivityCheckLoop{d: d, primary: primary, options: []*checkOption{primary, duplicate, alternative}}
	if result := loop.checkHealth(); !result.ok || result.networkType != alternativeType {
		t.Fatalf("health result = %+v, want successful alternative", result)
	}
	if got := primaryChecks.Load(); got != 2 {
		t.Fatalf("primary probes = %d, want one hedged check (2 probes)", got)
	}
}

func TestConnectivityRecheckDoesNotProbeUnknownAfterNodeRecovery(t *testing.T) {
	transport := new(statefulTestDialer)
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 4)}
	d.RegisterDialerGroup(group)

	healthType := common.IndexToNetworkType(0)
	unknownType := common.IndexToNetworkType(1)
	d.SetSupported(healthType, true)
	var healthChecks, capabilityChecks atomic.Int32
	healthOpt := &checkOption{
		networkType: healthType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			healthChecks.Add(1)
			return true, nil
		},
	}
	unknownOpt := &checkOption{
		networkType: unknownType,
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			capabilityChecks.Add(1)
			return true, nil
		},
	}

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(healthOpt, []*checkOption{healthOpt, unknownOpt})
	}()
	d.NotifyConnectivityRecheck()
	select {
	case avail := <-group.notified:
		if !avail.Alive {
			t.Fatalf("connectivity recheck published unhealthy status: %+v", avail)
		}
	case <-time.After(time.Second):
		t.Fatal("connectivity recheck did not recover node health")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if got := transport.connects.Load(); got != 1 {
		t.Fatalf("Connect calls = %d, want 1", got)
	}
	if got := healthChecks.Load(); got != 1 {
		t.Fatalf("health checks = %d, want 1", got)
	}
	if got := capabilityChecks.Load(); got != 0 {
		t.Fatalf("capability checks = %d, want 0", got)
	}
	if got := d.SupportState(unknownType); got != NetworkSupportUnknown {
		t.Fatalf("unknown capability became %s", got)
	}
	if !d.Alive() {
		t.Fatal("node did not recover globally")
	}
	if avail := stats.GetNode(d.StatsKey()); !avail.Alive {
		t.Fatalf("availability did not publish recovery: %+v", avail)
	}
}

func TestRunCheckLoopPublishesConsecutiveFailure(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 3)}
	d.RegisterDialerGroup(group)
	var checks atomic.Int32
	option := &checkOption{
		networkType: common.IndexToNetworkType(0),
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			checks.Add(1)
			return false, errors.New("probe failed")
		},
	}

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(option, []*checkOption{option})
	}()
	d.NotifyCheck()
	timeout := time.After(time.Second)

waitForFailure:
	for {
		select {
		case avail := <-group.notified:
			if avail.ChecksFailed == 1 {
				break waitForFailure
			}
		case <-timeout:
			t.Fatal("consecutive failure was not published")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	avail := stats.GetNode(d.StatsKey())
	if avail.ChecksTotal != 1 || avail.ChecksFailed != 1 {
		t.Fatalf("consecutive failure was not recorded once: %+v", avail)
	}
	if avail.LastFailureStartedAt.IsZero() {
		t.Fatalf("consecutive failure should start a failure episode: %+v", avail)
	}
	if got := checks.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
}

func TestInitialCheckPublishesFailedConnect(t *testing.T) {
	transport := &blockingFailConnectDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	close(transport.release)
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 1)}
	d.RegisterDialerGroup(group)
	checkOpts := []*checkOption{{
		networkType: common.IndexToNetworkType(0),
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			return true, nil
		},
	}}

	done := make(chan struct{})
	go func() {
		d.runInitialCheck(checkOpts)
		close(done)
	}()
	select {
	case avail := <-group.notified:
		if avail.ChecksFailed != 1 {
			t.Fatalf("notification observed %d failed checks, want 1", avail.ChecksFailed)
		}
	case <-time.After(time.Second):
		t.Fatal("initial failed Connect did not publish the dialer state")
	}
	if avail := stats.GetNode(d.StatsKey()); avail.ChecksTotal != 1 || avail.ChecksFailed != 1 {
		t.Fatalf("initial failed Connect was not recorded: %+v", avail)
	}
	d.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("initial check did not stop after cancellation")
	}
}

func TestInitialCheckDoesNotConnectAfterCancellation(t *testing.T) {
	transport := &failOnceConnectDialer{}
	d := newTestDialer(t, transport)
	d.cancel()

	if opt := d.runInitialCheck(nil); opt != nil {
		t.Fatal("canceled initial check unexpectedly selected an option")
	}
	if got := transport.calls.Load(); got != 0 {
		t.Fatalf("Connect calls after cancellation = %d, want 0", got)
	}
	if avail := stats.GetNode(d.StatsKey()); avail.Seen {
		t.Fatalf("canceled initial check should not be recorded: %+v", avail)
	}
}

func TestRunCheckLoopIgnoresTransientFailure(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 2)}
	d.RegisterDialerGroup(group)
	var checks atomic.Int32
	checkOpt := &checkOption{
		networkType: common.IndexToNetworkType(0),
		probe: func(context.Context, *common.NetworkType) (bool, error) {
			if checks.Add(1) == 1 {
				return false, errors.New("probe failed")
			}
			return true, nil
		},
	}

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(checkOpt, []*checkOption{checkOpt})
	}()
	d.NotifyCheck()
	timeout := time.After(time.Second)

waitForRetry:
	for {
		select {
		case avail := <-group.notified:
			if avail.Alive && avail.ChecksTotal == 1 {
				break waitForRetry
			}
		case <-timeout:
			t.Fatal("successful immediate retry was not published")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	avail := stats.GetNode(d.StatsKey())
	if !avail.Alive || avail.ChecksTotal != 1 || avail.ChecksFailed != 0 || avail.ChecksSinceAlive != 1 {
		t.Fatalf("transient failure should only publish the successful retry: %+v", avail)
	}
	if got := checks.Load(); got != 2 {
		t.Fatalf("health checks = %d, want 2", got)
	}
	latency, ok := d.LatencyStats(group)
	if !ok || latency.Avg10HasFailure {
		t.Fatalf("transient failure should not enter avg10: %+v, ok=%v", latency, ok)
	}
}

func TestRunCheckLoopDoesNotPublishAfterClose(t *testing.T) {
	transport := &blockingFailConnectDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 2)}
	d.RegisterDialerGroup(group)

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(nil, nil)
	}()
	d.NotifyCheck()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("Connect did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case <-d.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the dialer")
	}
	close(transport.release)

	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the in-flight Connect finished")
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("Connect calls after cancellation = %d, want 1", got)
	}
	if avail := stats.GetNode(d.StatsKey()); avail.Seen {
		t.Fatalf("canceled Connect should not be recorded: %+v", avail)
	}
	select {
	case <-group.notified:
		t.Fatal("canceled Connect unexpectedly published its result")
	default:
	}
}

func TestManualCheckStaggersNextSuccessfulIntervalOnce(t *testing.T) {
	d := newTestDialer(t, connectedTestDialer{})
	d.CheckInterval = time.Hour
	loop := newConnectivityCheckLoop(d, nil, nil)
	defer loop.healthTimer.Stop()
	defer loop.capabilityTimer.Stop()

	loop.staggerNext = true
	loop.publishHealth(healthCheckResult{err: errors.New("temporary failure")})
	if !loop.staggerNext {
		t.Fatal("failed check consumed pending stagger")
	}
	loop.publishHealth(healthCheckResult{ok: true})
	if loop.staggerNext {
		t.Fatal("successful check did not consume pending stagger")
	}
	spread := d.CheckInterval / 5
	if loop.healthInterval < d.CheckInterval-spread || loop.healthInterval > d.CheckInterval+spread {
		t.Fatalf("staggered interval = %v, want %v +/- %v", loop.healthInterval, d.CheckInterval, spread)
	}

	loop.publishHealth(healthCheckResult{ok: true})
	if loop.healthInterval != d.CheckInterval {
		t.Fatalf("following interval = %v, want %v", loop.healthInterval, d.CheckInterval)
	}
}

func TestRunCheckLoopDoesNotStartQueuedCheckAfterClose(t *testing.T) {
	transport := &failOnceConnectDialer{}
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	d.NotifyCheck()
	d.cancel()

	d.runCheckLoop(nil, nil)

	if got := transport.calls.Load(); got != 0 {
		t.Fatalf("Connect calls after cancellation = %d, want 0", got)
	}
}
