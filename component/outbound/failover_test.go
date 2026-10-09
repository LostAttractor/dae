// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type failoverTransport struct {
	sharedCheckTransport
	delay        atomic.Int64
	offline      atomic.Bool
	ipv6Offline  atomic.Bool
	attempts     atomic.Int32
	tcp4Attempts atomic.Int32
	tcp6Attempts atomic.Int32
	created      atomic.Int32
	closed       atomic.Int32
	ipv6Only     bool
}

func (d *failoverTransport) Close() error { d.closed.Add(1); return nil }

func (d *failoverTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, netproxy.UnsupportedTunnelTypeError
	}
	if d.ipv6Only && !strings.HasPrefix(address, "[") {
		return nil, netproxy.UnsupportedTunnelTypeError
	}
	d.attempts.Add(1)
	if strings.HasPrefix(address, "[") {
		d.tcp6Attempts.Add(1)
	} else {
		d.tcp4Attempts.Add(1)
	}
	timer := time.NewTimer(time.Duration(d.delay.Load()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	if d.offline.Load() || d.ipv6Offline.Load() && strings.HasPrefix(address, "[") {
		return nil, errors.New("proxy unavailable")
	}
	return d.sharedCheckTransport.DialContext(ctx, network, address)
}

func failoverGroup(t *testing.T, policy dialer.DialerSelectionPolicy, annotations []*dialer.Annotation, transports ...*failoverTransport) *DialerGroup {
	t.Helper()
	return newFailoverTestGroup(t, policy, annotations, false, transports...)
}

func newFailoverTestGroup(t *testing.T, policy dialer.DialerSelectionPolicy, annotations []*dialer.Annotation, recreate bool, transports ...*failoverTransport) *DialerGroup {
	t.Helper()
	option := &dialer.GlobalOption{CheckInterval: time.Second, CheckIntervalMax: time.Hour,
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1", "::1"}}}
	var nodes []*dialer.Dialer
	for i, transport := range transports {
		property := &dialer.Property{Name: string(rune('a' + i)), Link: t.Name() + string(rune('a'+i))}
		factory := func() (*netproxy.Runtime, error) { return netproxy.NewRuntime(netproxy.Layer{Data: transport}), nil }
		if recreate {
			node, err := dialer.NewRecreatableDialer(factory, option, property, "")
			if err != nil {
				t.Fatal(err)
			}
			nodes = append(nodes, node)
		} else {
			runtime, _ := factory()
			nodes = append(nodes, dialer.NewDialer(runtime, option, property, true, ""))
		}
	}
	if annotations == nil {
		annotations = emptyAnnotations(len(nodes))
	}
	group := NewDialerGroup(option, t.Name(), GroupKindSelector, nodes, annotations, policy, nil)
	t.Cleanup(func() { _ = group.Close() })
	start := make(chan struct{})
	if _, err := group.StartConnectivityChecks(start); err != nil {
		t.Fatal(err)
	}
	close(start)
	return group
}

func testFailoverPolicy() dialer.DialerSelectionPolicy {
	return dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Failover,
		FailureRecovery: 3 * time.Second,
		ProbeTimeout:    100 * time.Millisecond, SelectionTimeout: time.Second,
		UpgradeInterval: time.Second, UpgradeIntervalMax: 4 * time.Second}
}

func TestFailoverSleepsPeersAndUsesFirstVerifiedResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, low := new(failoverTransport), new(failoverTransport), new(failoverTransport)
		a.delay.Store(int64(5 * time.Millisecond))
		b.delay.Store(int64(20 * time.Millisecond))
		annotations := emptyAnnotations(3)
		annotations[0].Priority, annotations[1].Priority = 10, 10
		g := failoverGroup(t, testFailoverPolicy(), annotations, a, b, low)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if got := g.SelectedDialer(common.NetworkTCP4.NetworkType()); got != g.Dialers[0] {
			t.Fatalf("first response selected %v", got)
		}
		if low.attempts.Load() != 0 {
			t.Fatal("lower priority was probed despite available peers")
		}
		beforeA, beforeB := a.attempts.Load(), b.attempts.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		if a.attempts.Load() != beforeA || b.attempts.Load() != beforeB {
			t.Fatal("failover enabled periodic heartbeats")
		}
		a.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("upstream failed"))
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if got := g.SelectedDialer(common.NetworkTCP4.NetworkType()); got != g.Dialers[1] {
			t.Fatalf("failover selected %v", got)
		}
		if low.attempts.Load() != 0 {
			t.Fatal("same-priority failover probed a lower tier")
		}
	})
}

func TestFailoverHonorsOffsetsAndConditionalPriority(t *testing.T) {
	for _, conditional := range []bool{false, true} {
		t.Run(map[bool]string{false: "offset", true: "conditional"}[conditional], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := new(failoverTransport), new(failoverTransport)
				a.delay.Store(int64(5 * time.Millisecond))
				b.delay.Store(int64(20 * time.Millisecond))
				annotations := emptyAnnotations(2)
				annotations[1].AddLatency = -50 * time.Millisecond
				if conditional {
					annotations[0].Priority = 5
					annotations[1].ConditionalPriority = []*dialer.Priority{{Pri: 10, High: 50 * time.Millisecond}}
				}
				g := failoverGroup(t, testFailoverPolicy(), annotations, a, b)
				time.Sleep(200 * time.Millisecond)
				synctest.Wait()
				if got := g.SelectedDialer(common.NetworkTCP4.NetworkType()); got != g.Dialers[1] {
					t.Fatalf("weighted selection = %v", got)
				}
				if conditional && a.attempts.Load() != 0 {
					t.Fatal("lower static priority tested before conditional winner")
				}
			})
		})
	}
}

func TestFailoverTimeoutFallsThroughAndUpgradeWaitsForRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		high, low := new(failoverTransport), new(failoverTransport)
		high.delay.Store(int64(time.Second))
		low.delay.Store(int64(time.Millisecond))
		annotations := emptyAnnotations(2)
		annotations[0].Priority = 10
		annotations[0].AddLatency = -time.Hour
		g := failoverGroup(t, testFailoverPolicy(), annotations, high, low)
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if got := g.SelectedDialer(common.NetworkTCP4.NetworkType()); got != g.Dialers[1] {
			t.Fatalf("bounded fallback = %v", got)
		}
		high.delay.Store(int64(time.Millisecond))
		time.Sleep(1100 * time.Millisecond)
		synctest.Wait()
		if got := g.SelectedDialer(common.NetworkTCP4.NetworkType()); got != g.Dialers[1] {
			t.Fatal("penalty was bypassed by priority or negative offset")
		}
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if got := g.SelectedDialer(common.NetworkTCP4.NetworkType()); got != g.Dialers[0] {
			t.Fatalf("recovered high-priority path was not promoted: %v, %+v", got, g.Dialers[0].RuntimeStatus())
		}
	})
}

func TestContinuousSelectionSleepsLowerPriority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		high, peer, low := new(failoverTransport), new(failoverTransport), new(failoverTransport)
		high.delay.Store(int64(time.Millisecond))
		peer.delay.Store(int64(20 * time.Millisecond))
		annotations := emptyAnnotations(3)
		annotations[0].Priority, annotations[1].Priority = 10, 10
		policy := testFailoverPolicy()
		policy.Policy = consts.DialerSelectionPolicy_MinMovingAverageLatencies
		g := failoverGroup(t, policy, annotations, high, peer, low)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != g.Dialers[0] || high.attempts.Load() < 2 {
			t.Fatal("active tier not monitored")
		}
		if low.attempts.Load() != 0 {
			t.Fatal("lower priority was tested despite a usable serving-tier peer")
		}
		peer.offline.Store(true)
		g.Dialers[1].ReportDataPlaneError(errors.New("peer failed"))
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if low.attempts.Load() == 0 || !g.Dialers[2].RuntimeStatus().CheckEnabled {
			t.Fatal("loss of the only peer did not wake lower-tier backups")
		}
		peer.offline.Store(false)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		before := low.attempts.Load()
		if g.Dialers[2].RuntimeStatus().CheckEnabled {
			t.Fatal("recovered serving-tier peer did not release lower-tier monitoring")
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if low.attempts.Load() != before {
			t.Fatal("lower tier kept probing after peer recovery")
		}
	})
}

func TestContinuousSinglePrimaryKeepsLowerTierWarm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		high, low := new(failoverTransport), new(failoverTransport)
		high.delay.Store(int64(time.Millisecond))
		low.delay.Store(int64(10 * time.Millisecond))
		annotations := emptyAnnotations(2)
		annotations[0].Priority = 1
		policy := testFailoverPolicy()
		policy.Policy = consts.DialerSelectionPolicy_MinMovingAverageLatencies
		g := newFailoverTestGroup(t, policy, annotations, true, high, low)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if got := g.SelectedDialer(testNetworkType); got != g.Dialers[0] {
			t.Fatal("backup replaced a healthy higher-priority primary")
		}
		status := g.Dialers[1].RuntimeStatus()
		if !status.Healthy || !status.HasLatency || !status.CheckEnabled {
			t.Fatalf("single primary left backup cold: %+v", status)
		}
		before := low.attempts.Load()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if low.attempts.Load() <= before {
			t.Fatal("backup did not receive ongoing health checks")
		}
		high.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("primary failed"))
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		began := time.Now()
		selected, err := g.Select(testNetworkType)
		if err != nil || selected != g.Dialers[1] || time.Since(began) > 30*time.Millisecond {
			t.Fatalf("warm failover = %v, %v after %v", selected, err, time.Since(began))
		}
	})
}

func TestContinuousPeerMustSupportTheSameNetwork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		high, peer, low := new(failoverTransport), &failoverTransport{ipv6Only: true}, new(failoverTransport)
		high.delay.Store(int64(time.Millisecond))
		peer.delay.Store(int64(20 * time.Millisecond))
		annotations := emptyAnnotations(3)
		annotations[0].Priority, annotations[1].Priority = 1, 1
		policy := testFailoverPolicy()
		policy.Policy = consts.DialerSelectionPolicy_MinMovingAverageLatencies
		g := failoverGroup(t, policy, annotations, high, peer, low)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if g.Dialers[1].Usable(common.NetworkTCP4.NetworkType()) || !g.Dialers[1].Usable(common.NetworkTCP6.NetworkType()) {
			t.Fatal("test peer did not expose the intended capability split")
		}
		if !g.Dialers[2].RuntimeStatus().CheckEnabled || !g.Dialers[2].Usable(common.NetworkTCP4.NetworkType()) {
			t.Fatal("IPv6-only peer caused the IPv4 backup to sleep")
		}
	})
}

func TestContinuousAliasesDoNotCountAsIndependentPeers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		option := &dialer.GlobalOption{CheckInterval: time.Second, CheckIntervalMax: time.Hour,
			CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1", "::1"}}}
		highTransport, lowTransport := new(failoverTransport), new(failoverTransport)
		newNode := func(name string, transport *failoverTransport) *dialer.Dialer {
			return dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: transport}), option, &dialer.Property{Name: name, Link: t.Name() + name}, true, "")
		}
		high, low := newNode("primary", highTransport), newNode("backup", lowTransport)
		alias, ok := high.Share(&dialer.Property{Name: "alias", Link: t.Name() + "alias"}, "")
		if !ok {
			t.Fatal("could not share primary runtime")
		}
		annotations := emptyAnnotations(3)
		annotations[0].Priority, annotations[1].Priority = 1, 1
		policy := testFailoverPolicy()
		policy.Policy = consts.DialerSelectionPolicy_MinMovingAverageLatencies
		g := NewDialerGroup(option, t.Name(), GroupKindSelector, []*dialer.Dialer{high, alias, low}, annotations, policy, nil)
		defer g.Close()
		start := make(chan struct{})
		if _, err := g.StartConnectivityChecks(start); err != nil {
			t.Fatal(err)
		}
		close(start)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if !low.RuntimeStatus().CheckEnabled || lowTransport.attempts.Load() == 0 {
			t.Fatal("two aliases of one physical path caused the independent backup to sleep")
		}
	})
}

func TestFailoverReleasesOnlyIdleUnselectedTransports(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		option := &dialer.GlobalOption{CheckInterval: time.Hour, CheckIntervalMax: time.Hour,
			CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1", "::1"}}}
		a, b := new(failoverTransport), new(failoverTransport)
		a.delay.Store(int64(time.Millisecond))
		b.delay.Store(int64(10 * time.Millisecond))
		var nodes []*dialer.Dialer
		for i, transport := range []*failoverTransport{a, b} {
			d, err := dialer.NewRecreatableDialer(func() (*netproxy.Runtime, error) {
				transport.created.Add(1)
				return netproxy.NewRuntime(netproxy.Layer{Data: transport, Resources: []io.Closer{transport}}), nil
			}, option, &dialer.Property{Name: string(rune('a' + i)), Link: t.Name() + string(rune('a'+i))}, "")
			if err != nil {
				t.Fatal(err)
			}
			nodes = append(nodes, d)
		}
		annotations := emptyAnnotations(2)
		annotations[0].Priority = 10
		g := NewDialerGroup(option, t.Name(), GroupKindSelector, nodes, annotations, testFailoverPolicy(), nil)
		defer g.Close()
		start := make(chan struct{})
		_, err := g.StartConnectivityChecks(start)
		if err != nil {
			t.Fatal(err)
		}
		close(start)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != nodes[0] {
			t.Fatal("physical generation proof was lost before selection")
		}
		if a.created.Load()-a.closed.Load() != 1 || b.created.Load() != b.closed.Load() {
			t.Fatalf("physical sessions: selected=%d/%d standby=%d/%d", a.created.Load(), a.closed.Load(), b.created.Load(), b.closed.Load())
		}
		if nodes[1].RuntimeStatus().Degraded {
			t.Fatal("sleep was treated as a fault")
		}
		before := b.attempts.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		if b.attempts.Load() != before {
			t.Fatal("sleeping standby generated traffic")
		}
		a.offline.Store(true)
		nodes[0].ReportDataPlaneError(errors.New("connection lost"))
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != nodes[1] {
			t.Fatal("sleeping candidate failed to wake and replace failed node")
		}
		a.offline.Store(false)
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != nodes[0] {
			t.Fatalf("sleep between upgrade checks lost recovery progress: %+v", nodes[0].RuntimeStatus())
		}
	})
}

func TestFailoverVerifiesCachedPeerAndFallsBackToDegraded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := new(failoverTransport), new(failoverTransport)
		a.delay.Store(int64(time.Millisecond))
		b.delay.Store(int64(10 * time.Millisecond))
		policy := testFailoverPolicy()
		policy.FailureRecovery = time.Hour
		g := failoverGroup(t, policy, nil, a, b)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		b.offline.Store(true)
		a.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("upstream lost"))
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != nil {
			t.Fatal("stale healthy peer was selected without verification")
		}
		b.offline.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != g.Dialers[1] || !g.Dialers[1].RuntimeStatus().Degraded {
			t.Fatal("available degraded peer was not used as fallback")
		}
	})
}

func TestFailoverKeepsPublishedRouteDuringBoundedReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := new(failoverTransport), new(failoverTransport)
		a.delay.Store(int64(time.Millisecond))
		b.delay.Store(int64(20 * time.Millisecond))
		g := failoverGroup(t, testFailoverPolicy(), nil, a, b)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		var down atomic.Int32
		detach, err := g.ObserveConnectivity(func(available bool, network *common.NetworkType) error {
			if !available && network.Index() == common.NetworkTCP4 {
				down.Add(1)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer detach()
		a.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("upstream lost"))
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		if down.Load() != 0 {
			t.Fatal("replacement transiently published direct fallback")
		}
		result := make(chan ConnectionSelection, 1)
		go func() { selected, _ := g.SelectConnection(*common.NetworkTCP4.NetworkType(), true); result <- selected }()
		synctest.Wait()
		select {
		case <-result:
			t.Fatal("request escaped before replacement verification")
		default:
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if selected := <-result; selected.Dialer != g.Dialers[1] || down.Load() != 0 {
			t.Fatal("bounded selection lost original outbound admission")
		}
	})
}

func TestRecoveryEndpointProofPromotesWithoutAnotherProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		high, low := new(failoverTransport), new(failoverTransport)
		high.offline.Store(true)
		high.delay.Store(int64(time.Millisecond))
		low.delay.Store(int64(time.Millisecond))
		annotations := emptyAnnotations(2)
		annotations[0].Priority = 10
		policy := testFailoverPolicy()
		policy.FailureRecovery = 2500 * time.Millisecond
		policy.UpgradeInterval, policy.UpgradeIntervalMax = 100*time.Millisecond, 100*time.Millisecond
		g := newFailoverTestGroup(t, policy, annotations, true, high, low)
		gate := make(chan struct{})
		release := sync.OnceFunc(func() { close(gate) })
		defer release()
		observer := &delayedSelectionObserver{group: g, gate: gate, entered: make(chan struct{}, 1)}
		g.Dialers[0].RegisterDialerGroup(observer, policy.WithDefaults().EmaAlpha, policy.FailureRecovery, policy.ProbeTimeout)
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		high.offline.Store(false)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		status := g.Dialers[0].RuntimeStatus()
		if !status.Degraded || !status.CheckEnabled || !status.Healthy {
			t.Fatalf("observation did not start: %+v", status)
		}
		deadline := status.MeasuredAt.Add(policy.FailureRecovery - status.RecoveryElapsed)
		before := high.attempts.Load()
		before6 := high.tcp6Attempts.Load()
		time.Sleep(time.Until(deadline) - 20*time.Millisecond)
		high.delay.Store(int64(50 * time.Millisecond))
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		began := time.Now()
		selected, err := g.Select(testNetworkType)
		if err != nil || selected != g.Dialers[1] || time.Since(began) != 0 {
			t.Fatal("business waited for recovery or switched before endpoint verification")
		}
		if !g.Dialers[0].RuntimeStatus().Degraded {
			t.Fatal("elapsed time lifted degradation while endpoint test was still running")
		}
		// Delay delivery to the selector beyond the probe's completion. Reuse
		// must survive scheduling latency, not just an identical clock tick.
		observer.delay.Store(true)
		time.Sleep(100 * time.Millisecond)
		select {
		case <-observer.entered:
		default:
			t.Fatal("endpoint result was not held for delayed delivery")
		}
		release()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[0] || g.Dialers[0].RuntimeStatus().Degraded {
			t.Fatal("endpoint success did not restore priority")
		}
		if got, got6 := high.attempts.Load()-before, high.tcp6Attempts.Load()-before6; got != 4 || got6 != 3 {
			t.Fatalf("recovery probes = %d (TCP6=%d), want two interval probes, one TCP6 endpoint and one TCP4 handoff verification", got, got6)
		}
		before = high.attempts.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		if high.attempts.Load() != before {
			t.Fatal("completed recovery kept probing")
		}
	})
}

type delayedSelectionObserver struct {
	group   *DialerGroup
	gate    <-chan struct{}
	entered chan struct{}
	delay   atomic.Bool
}

func (o *delayedSelectionObserver) DialerChanged(d *dialer.Dialer, force dialer.SelectionForceMask) {
	if o.delay.Swap(false) {
		o.entered <- struct{}{}
		<-o.gate
	}
	o.group.DialerChanged(d, force)
}

func TestElectionReturnsOnFirstVerifiedPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fast, slow := new(failoverTransport), new(failoverTransport)
		fast.delay.Store(int64(time.Millisecond))
		slow.delay.Store(int64(90 * time.Millisecond))
		g := failoverGroup(t, testFailoverPolicy(), nil, fast, slow)
		began := time.Now()
		selected, err := g.Select(testNetworkType)
		if err != nil || selected != g.Dialers[0] || time.Since(began) > 5*time.Millisecond {
			t.Fatalf("selection waited for slow peer: %v, %v after %v", selected, err, time.Since(began))
		}
	})
}

func TestElectionDoesNotWaitForDominatedOffset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fast, slow := new(failoverTransport), new(failoverTransport)
		fast.delay.Store(int64(time.Millisecond))
		slow.delay.Store(int64(time.Hour))
		annotations := emptyAnnotations(2)
		annotations[1].AddLatency = time.Second
		g := failoverGroup(t, testFailoverPolicy(), annotations, fast, slow)
		began := time.Now()
		selected, err := g.Select(testNetworkType)
		if err != nil || selected != g.Dialers[0] || time.Since(began) > 5*time.Millisecond {
			t.Fatalf("dominated candidate delayed selection: %v, %v after %v", selected, err, time.Since(began))
		}
	})
}

func TestRecoveryFailureRestartsTheWholeWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		high, low := new(failoverTransport), new(failoverTransport)
		high.offline.Store(true)
		high.delay.Store(int64(time.Millisecond))
		annotations := emptyAnnotations(2)
		annotations[0].Priority = 10
		policy := testFailoverPolicy()
		policy.UpgradeInterval, policy.UpgradeIntervalMax = 100*time.Millisecond, 100*time.Millisecond
		g := failoverGroup(t, policy, annotations, high, low)
		time.Sleep(100 * time.Millisecond)
		high.offline.Store(false)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		status := g.Dialers[0].RuntimeStatus()
		deadline := status.MeasuredAt.Add(policy.FailureRecovery - status.RecoveryElapsed)
		time.Sleep(time.Until(deadline) - 20*time.Millisecond)
		high.offline.Store(true)
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if status := g.Dialers[0].RuntimeStatus(); !status.Degraded || status.RecoveryElapsed != 0 {
			t.Fatalf("failed endpoint preserved progress: %+v", status)
		}
		high.offline.Store(false)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		status = g.Dialers[0].RuntimeStatus()
		if !status.Healthy || !status.Degraded {
			t.Fatalf("new observation did not start degraded: %+v", status)
		}
		deadline = status.MeasuredAt.Add(policy.FailureRecovery - status.RecoveryElapsed)
		time.Sleep(time.Until(deadline) - time.Millisecond)
		if g.SelectedDialer(testNetworkType) != g.Dialers[1] {
			t.Fatal("failure did not require a complete new window")
		}
		time.Sleep(20 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
			t.Fatal("new completed window did not promote the recovered path")
		}
	})
}

func TestElectionRetainsRunnerUpWhenBestProofExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		best, backup, pending := new(failoverTransport), new(failoverTransport), new(failoverTransport)
		best.delay.Store(int64(time.Millisecond))
		backup.delay.Store(int64(10 * time.Millisecond))
		pending.delay.Store(int64(80 * time.Millisecond))
		pending.offline.Store(true)
		annotations := emptyAnnotations(3)
		annotations[2].AddLatency = -time.Second
		g := failoverGroup(t, testFailoverPolicy(), annotations, best, backup, pending)
		time.Sleep(30 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != nil || !g.Dialers[1].Usable(testNetworkType) {
			t.Fatal("election did not wait with a verified runner-up")
		}
		best.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("best failed while weighted peer was pending"))
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[1] {
			t.Fatal("expired best proof hid an already verified runner-up")
		}
	})
}

func TestSelectionWaitBudgetSurvivesElectionReplacement(t *testing.T) {
	for name, selectPath := range map[string]func(*DialerGroup){
		"Select":        func(g *DialerGroup) { _, _ = g.Select(testNetworkType) },
		"strict IP":     func(g *DialerGroup) { _, _ = g.SelectConnection(*testNetworkType, true) },
		"both families": func(g *DialerGroup) { _, _ = g.SelectConnection(*testNetworkType, false) },
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy := testFailoverPolicy()
				g := NewDialerGroup(&dialer.GlobalOption{}, t.Name(), GroupKindSelector, nil, nil, policy, nil)
				defer g.Close()
				// Hold publication while simulating canceled/replaced background
				// jobs. A waiting request must keep its original deadline.
				g.automatic.started = true
				done := make(chan time.Duration, 1)
				go func() {
					began := time.Now()
					selectPath(g)
					done <- time.Since(began)
				}()
				for range 3 {
					time.Sleep(policy.SelectionTimeout / 2)
					g.mu.Lock()
					for network := range common.NetworkIndex(common.NetworkTypeCount) {
						g.automatic.changedLocked(network)
					}
					g.mu.Unlock()
				}
				synctest.Wait()
				select {
				case elapsed := <-done:
					if elapsed != policy.SelectionTimeout {
						t.Fatalf("waited %v, want one shared budget of %v", elapsed, policy.SelectionTimeout)
					}
				default:
					t.Fatal("request outlived selection_timeout across election changes")
				}
			})
		})
	}
}

func TestContinuousMonitoringOwnsKnownCapabilityChecks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conditional, primary := new(failoverTransport), new(failoverTransport)
		conditional.delay.Store(int64(20 * time.Millisecond))
		primary.delay.Store(int64(time.Millisecond))
		annotations := emptyAnnotations(2)
		annotations[0].ConditionalPriority = []*dialer.Priority{{Pri: 10, High: 5 * time.Millisecond}}
		annotations[1].Priority = 5
		policy := testFailoverPolicy()
		policy.Policy = consts.DialerSelectionPolicy_MinMovingAverageLatencies
		policy.UpgradeInterval, policy.UpgradeIntervalMax = 50*time.Millisecond, 50*time.Millisecond
		g := failoverGroup(t, policy, annotations, conditional, primary)
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[1] || !g.Dialers[0].RuntimeStatus().CheckEnabled {
			t.Fatal("conditional candidate was not monitored as a lower-tier backup")
		}
		before := conditional.attempts.Load()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if got := conditional.attempts.Load() - before; got > 1 {
			t.Fatalf("upgrade scheduler duplicated continuous monitoring: %d probes in half a check interval", got)
		}
		conditional.delay.Store(int64(time.Millisecond))
		time.Sleep(15 * time.Second)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
			t.Fatal("continuous samples did not promote the newly eligible priority")
		}
	})
}
