// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
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
	blockAfter   atomic.Int32
	blocked      atomic.Int32
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
	attempt := d.attempts.Add(1)
	if strings.HasPrefix(address, "[") {
		d.tcp6Attempts.Add(1)
	} else {
		d.tcp4Attempts.Add(1)
	}
	if after := d.blockAfter.Load(); after > 0 && attempt > after {
		d.blocked.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
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

// awaitRecoveryAttempt lets a failed path reach its own next recovery attempt:
// groups no longer probe it, whatever their upgrade interval.
func awaitRecoveryAttempt(d *dialer.Dialer) {
	time.Sleep(time.Until(d.RuntimeStatus().Recovery.RetryAt) + 200*time.Millisecond)
	synctest.Wait()
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
	group := NewDialerGroup(option, t.Name(), GroupKindSelector, nodes, annotations, policy)
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
		low.delay.Store(int64(50 * time.Millisecond))
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
		// Fail the primary just after a periodic backup check, so the next
		// periodic check cannot overlap the takeover.
		before = low.attempts.Load()
		for low.attempts.Load() == before {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(60 * time.Millisecond)
		synctest.Wait()
		before = low.attempts.Load()
		high.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("primary failed"))
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		began := time.Now()
		selected, err := g.Select(t.Context(), testNetworkType)
		if err != nil || selected != g.Dialers[1] || time.Since(began) != 0 {
			t.Fatalf("warm failover = %v, %v after %v", selected, err, time.Since(began))
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if got := low.attempts.Load() - before; got != 1 || g.SelectedDialer(testNetworkType) != g.Dialers[1] {
			t.Fatalf("takeover verified the backup with %d probes, want one", got)
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
		g := NewDialerGroup(option, t.Name(), GroupKindSelector, []*dialer.Dialer{high, alias, low}, annotations, policy)
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
		g := NewDialerGroup(option, t.Name(), GroupKindSelector, nodes, annotations, testFailoverPolicy())
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
			t.Fatal("selected physical generation was lost before selection")
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

func TestFailoverVerifiesStalePeerAfterTakeover(t *testing.T) {
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
		before := b.attempts.Load()
		g.Dialers[0].ReportDataPlaneError(errors.New("upstream lost"))
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != g.Dialers[1] {
			t.Fatal("alive peer did not take over before its verification")
		}
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != nil || b.attempts.Load() == before {
			t.Fatal("failed verification did not remove the stale peer")
		}
		b.offline.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if g.SelectedDialer(common.NetworkTCP4.NetworkType()) != g.Dialers[1] || !g.Dialers[1].RuntimeStatus().Degraded {
			t.Fatal("available degraded peer was not used as fallback")
		}
	})
}

// Until its first election succeeds or fails, an automatic group publishes the
// network as electing, so requests wait for the result instead of degrading. A
// network no candidate supports does not elect.
func TestStartupElectionPublishesElecting(t *testing.T) {
	for _, offline := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			transport := new(failoverTransport)
			transport.delay.Store(int64(50 * time.Millisecond))
			transport.offline.Store(offline)
			g := newFailoverTestGroup(t, testFailoverPolicy(), nil, true, transport)
			var mu sync.Mutex
			var published []Connectivity
			detach, err := g.ObserveConnectivity(func(update Connectivity) error {
				if update.Network.Index() == common.NetworkTCP4 {
					mu.Lock()
					published = append(published, update)
					mu.Unlock()
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer detach()
			time.Sleep(500 * time.Millisecond)
			synctest.Wait()
			mu.Lock()
			defer mu.Unlock()
			if len(published) != 2 || published[0].Available || !published[0].Electing ||
				published[1].Available == offline || published[1].Electing {
				t.Fatalf("offline=%v: published %+v, want electing then the result", offline, published)
			}
			if udp4 := *common.NetworkUDP4.NetworkType(); g.Available(udp4) || g.Electing(udp4) {
				t.Fatalf("offline=%v: unsupported udp4 still elects", offline)
			}
		})
	}
}

func TestFailoverKeepsPublishedRouteDuringBoundedReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, low := new(failoverTransport), new(failoverTransport), new(failoverTransport)
		a.delay.Store(int64(time.Millisecond))
		b.delay.Store(int64(20 * time.Millisecond))
		annotations := emptyAnnotations(3)
		annotations[0].Priority, annotations[1].Priority = 1, 1
		g := newFailoverTestGroup(t, testFailoverPolicy(), annotations, true, a, b, low)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if g.Dialers[1].Alive(testNetworkType) || g.Dialers[2].Alive(testNetworkType) {
			t.Fatal("fixture left an unmonitored failover peer awake")
		}
		lowBefore := low.attempts.Load()
		var down atomic.Int32
		detach, err := g.ObserveConnectivity(func(update Connectivity) error {
			if !update.Available && update.Network.Index() == common.NetworkTCP4 {
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
		go func() {
			selected, _ := g.SelectConnection(t.Context(), *common.NetworkTCP4.NetworkType(), true)
			result <- selected
		}()
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
		if low.attempts.Load() != lowBefore {
			t.Fatal("election tested a lower tier before the serving tier")
		}
	})
}

// A takeover by a lower tier serves at once and tests an untested better
// tier without waiting for the upgrade interval.
func TestLowerTierTakeoverTestsUntestedTierAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, low := new(failoverTransport), new(failoverTransport), new(failoverTransport)
		a.delay.Store(int64(time.Millisecond))
		b.delay.Store(int64(20 * time.Millisecond))
		annotations := emptyAnnotations(3)
		annotations[0].Priority, annotations[1].Priority = 2, 1
		g := newFailoverTestGroup(t, testFailoverPolicy(), annotations, true, a, b, low)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if b.attempts.Load() != 0 {
			t.Fatal("fixture tested the middle tier")
		}
		// Another owner keeps the lowest tier alive.
		release, err := g.Dialers[2].Check(t.Context(), common.NetworkTCP4, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		a.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("upstream lost"))
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[2] {
			t.Fatal("the alive lower tier did not take over")
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[1] {
			t.Fatal("the untested middle tier was not tested at once")
		}
	})
}

func TestRecoveryEndpointCheckPromotesWithoutAnotherProbe(t *testing.T) {
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
		g.Dialers[0].RegisterDialerGroup(observer, policy.WithDefaults())
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		high.offline.Store(false)
		awaitRecoveryAttempt(g.Dialers[0])
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
		selected, err := g.Select(t.Context(), testNetworkType)
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
		if got, got6 := high.attempts.Load()-before, high.tcp6Attempts.Load()-before6; got != 3 || got6 != 3 {
			t.Fatalf("recovery probes = %d (TCP6=%d), want two interval probes and one shared endpoint verification", got, got6)
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
		selected, err := g.Select(t.Context(), testNetworkType)
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
		selected, err := g.Select(t.Context(), testNetworkType)
		if err != nil || selected != g.Dialers[0] || time.Since(began) > 5*time.Millisecond {
			t.Fatalf("dominated candidate delayed selection: %v, %v after %v", selected, err, time.Since(began))
		}
	})
}

// A failed candidate recovers on its path's schedule: every automatic group
// keeps it monitored, and upgrade checks no longer probe it.
func TestFailedCandidateRecoversWithoutUpgradeProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		high, low := new(failoverTransport), new(failoverTransport)
		high.offline.Store(true)
		annotations := emptyAnnotations(2)
		annotations[0].Priority = 10
		policy := testFailoverPolicy()
		policy.UpgradeInterval, policy.UpgradeIntervalMax = 100*time.Millisecond, 100*time.Millisecond
		g := failoverGroup(t, policy, annotations, high, low)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		snapshot := g.Dialers[0].SelectionSnapshot(testNetworkType)
		if !snapshot.Recovering() || !g.Dialers[0].RuntimeStatus().CheckEnabled {
			t.Fatalf("automatic group left its failed candidate unmonitored: %+v", snapshot)
		}
		// About ten attempts of both TCP modes; 100ms upgrade checks made about a hundred.
		if attempts := high.attempts.Load(); attempts > 30 {
			t.Fatalf("failed candidate was probed %d times in 10s", attempts)
		}
		high.offline.Store(false)
		awaitRecoveryAttempt(g.Dialers[0])
		if !g.Dialers[0].RuntimeStatus().Healthy {
			t.Fatal("failed candidate did not recover by itself")
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
		awaitRecoveryAttempt(g.Dialers[0])
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
		awaitRecoveryAttempt(g.Dialers[0])
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

// The first alive candidate serves at once. The election continues and
// commits a later result only when it is strictly better.
func TestElectionServesFirstAliveThenCommitsOnlyBetter(t *testing.T) {
	for _, weightedOnline := range []bool{false, true} {
		t.Run(map[bool]string{false: "runner-up", true: "better"}[weightedOnline], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				best, backup, weighted := new(failoverTransport), new(failoverTransport), new(failoverTransport)
				best.delay.Store(int64(time.Millisecond))
				backup.delay.Store(int64(10 * time.Millisecond))
				// It answers after the others, within the probe timeout.
				weighted.delay.Store(int64(40 * time.Millisecond))
				weighted.offline.Store(!weightedOnline)
				annotations := emptyAnnotations(3)
				annotations[2].AddLatency = -time.Second
				g := failoverGroup(t, testFailoverPolicy(), annotations, best, backup, weighted)
				time.Sleep(30 * time.Millisecond)
				synctest.Wait()
				if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
					t.Fatal("an alive candidate did not serve while the election continued")
				}
				if weightedOnline {
					time.Sleep(100 * time.Millisecond)
					synctest.Wait()
					if g.SelectedDialer(testNetworkType) != g.Dialers[2] {
						t.Fatal("the election did not commit a better candidate after the takeover")
					}
					return
				}
				best.offline.Store(true)
				g.Dialers[0].ReportDataPlaneError(errors.New("best failed while weighted peer was pending"))
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				if g.SelectedDialer(testNetworkType) != g.Dialers[1] {
					t.Fatal("a failed best candidate hid an already tested runner-up")
				}
			})
		})
	}
}

func TestSelectionWaitBudgetSurvivesElectionReplacement(t *testing.T) {
	for name, selectPath := range map[string]func(context.Context, *DialerGroup){
		"Select":        func(ctx context.Context, g *DialerGroup) { _, _ = g.Select(ctx, testNetworkType) },
		"strict IP":     func(ctx context.Context, g *DialerGroup) { _, _ = g.SelectConnection(ctx, *testNetworkType, true) },
		"both families": func(ctx context.Context, g *DialerGroup) { _, _ = g.SelectConnection(ctx, *testNetworkType, false) },
	} {
		for _, deadline := range []time.Duration{0, 10 * time.Millisecond} {
			t.Run(fmt.Sprint(name, " deadline=", deadline), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					policy := testFailoverPolicy()
					g := NewDialerGroup(&dialer.GlobalOption{}, t.Name(), GroupKindSelector, nil, nil, policy)
					defer g.Close()
					// Hold publication while simulating canceled/replaced background
					// jobs. A waiting request must keep its original deadline.
					g.automatic.started = true
					want, ctx := policy.SelectionTimeout, t.Context()
					if deadline != 0 {
						var cancel context.CancelFunc
						ctx, cancel = context.WithTimeout(ctx, deadline)
						defer cancel()
						want = deadline
					}
					done := make(chan time.Duration, 1)
					go func() {
						began := time.Now()
						selectPath(ctx, g)
						done <- time.Since(began)
					}()
					for range 3 {
						time.Sleep(policy.SelectionTimeout / 2)
						g.automatic.mu.Lock()
						for network := range common.NetworkIndex(common.NetworkTypeCount) {
							g.automatic.changedLocked(network)
						}
						g.automatic.mu.Unlock()
					}
					synctest.Wait()
					select {
					case elapsed := <-done:
						if elapsed != want {
							t.Fatalf("waited %v, want one shared budget of %v", elapsed, want)
						}
					default:
						t.Fatal("request outlived its budget across election changes")
					}
				})
			})
		}
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

// A network served without an election, e.g. by a peer that is alive for
// another group or by monitored paths recovering after an outage, elects at
// once when its path fails instead of waiting out earlier elections' backoff.
func TestServedNetworkElectsWithoutEarlierBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		primary, backup := new(failoverTransport), new(failoverTransport)
		annotations := emptyAnnotations(2)
		annotations[0].Priority = 10
		policy := testFailoverPolicy()
		policy.UpgradeIntervalMax = time.Hour
		// Recreatable paths sleep: the backup is not alive and needs an election.
		g := newFailoverTestGroup(t, policy, annotations, true, primary, backup)
		time.Sleep(time.Second)
		synctest.Wait()
		g.automatic.mu.Lock()
		state := &g.automatic.networks[common.NetworkTCP4]
		state.retryAt, state.unavailable = time.Now().Add(time.Hour), time.Now().Add(-4*time.Hour)
		g.automatic.mu.Unlock()
		g.DialerChanged(g.Dialers[0], dialer.SelectionForceNone)
		primary.offline.Store(true)
		g.Dialers[0].ReportDataPlaneError(errors.New("upstream failed"))
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[1] {
			t.Fatal("a served network waited out the backoff of earlier elections")
		}
	})
}

// A forced decision ignores the tolerance once; later samples apply it again.
func TestForcedSelectionAppliesToOneDecision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := new(failoverTransport), new(failoverTransport)
		a.delay.Store(int64(10 * time.Millisecond))
		b.delay.Store(int64(30 * time.Millisecond))
		option := &dialer.GlobalOption{CheckInterval: time.Second, CheckIntervalMax: time.Hour, CheckTolerance: 50 * time.Millisecond,
			CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1", "::1"}}}
		var nodes []*dialer.Dialer
		for i, transport := range []*failoverTransport{a, b} {
			runtime := netproxy.NewRuntime(netproxy.Layer{Data: transport})
			nodes = append(nodes, dialer.NewDialer(runtime, option, &dialer.Property{Name: string(rune('a' + i)), Link: t.Name() + string(rune('a'+i))}, true, ""))
		}
		policy := testFailoverPolicy()
		policy.Policy = consts.DialerSelectionPolicy_MinLastLatency
		g := NewDialerGroup(option, t.Name(), GroupKindSelector, nodes, emptyAnnotations(2), policy)
		defer g.Close()
		start := make(chan struct{})
		if _, err := g.StartConnectivityChecks(start); err != nil {
			t.Fatal(err)
		}
		close(start)
		time.Sleep(time.Second)
		synctest.Wait()
		g.EnableSelectionTolerance()
		if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
			t.Fatal("the faster path was not selected")
		}
		// b confirms a capability; the decision it forces keeps the faster a.
		g.DialerChanged(g.Dialers[1], dialer.SelectionForceFor(common.NetworkTCP4))
		b.delay.Store(int64(5 * time.Millisecond))
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
			t.Fatal("a sample within the tolerance switched paths after a forced decision")
		}
	})
}
