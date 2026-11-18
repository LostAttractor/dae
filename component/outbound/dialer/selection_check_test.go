// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestSelectionCheckExpiredBudgetDoesNotStartWork(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newTestDialer(t, testTransport{})
				d.SetCheckEnabled(false)
				began := time.Now()
				release, err := d.Check(t.Context(), common.NetworkTCP4, timeout)
				if release != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(began) != 0 {
					t.Fatalf("expired budget was extended: err=%v elapsed=%v", err, time.Since(began))
				}
				if status := d.RuntimeStatus(); status.Checking || !status.CheckedAt.IsZero() || d.connectivityCheckRequested() {
					t.Fatalf("expired budget requested a check: %+v", status)
				}
			})
		})
	}
}

func TestSelectionChecksCoalesceAndBoundQueueing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		var probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, _ *common.NetworkType) error {
			probes.Add(1)
			select {
			case <-time.After(10 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		var clients sync.WaitGroup
		for range 8 {
			clients.Go(func() {
				release, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
				if err != nil || !d.Alive(common.NetworkTCP4.NetworkType()) {
					t.Errorf("check did not make the path alive: %v", err)
					return
				}
				release()
			})
		}
		clients.Wait()
		if probes.Load() != 1 {
			t.Fatalf("coalesced calls probed %d times", probes.Load())
		}
	})
}

func TestSelectionCheckQueueTimeout(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.SetCheckEnabled(false)
	d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}}})
	startConfirmation(d)
	checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
		t.Error("queued check reached the network")
		return nil
	})
	start := make(chan struct{})
	close(start)
	var worker sync.WaitGroup
	worker.Go(func() { checker.run(start) })
	defer func() { _ = d.Close(); worker.Wait() }()
	for range cap(connectivityCheckSlots) {
		connectivityCheckSlots <- struct{}{}
	}
	defer func() {
		for range cap(connectivityCheckSlots) {
			<-connectivityCheckSlots
		}
	}()
	before := d.RuntimeStatus()
	_, err := d.Check(t.Context(), common.NetworkTCP4, time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queue error=%v", err)
	}
	after := d.RuntimeStatus()
	if after.Degraded || !after.Healthy || after.Latency != before.Latency {
		t.Fatal("queue timeout poisoned node health or latency")
	}
}

func TestSharedCheckHonorsEachCallersDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		var probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, _ *common.NetworkType) error {
			probes.Add(1)
			select {
			case <-time.After(50 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		long := make(chan error, 1)
		go func() {
			release, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
			if err == nil {
				release()
			}
			long <- err
		}()
		synctest.Wait()
		began := time.Now()
		_, err := d.Check(t.Context(), common.NetworkTCP4, 10*time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) != 10*time.Millisecond {
			t.Fatalf("short waiter: %v after %v", err, time.Since(began))
		}
		if err := <-long; err != nil {
			t.Fatalf("short deadline canceled shared operation: %v", err)
		}
		if probes.Load() != 1 {
			t.Fatal("shared callers produced duplicate probes")
		}
	})
}

func TestRecoveryRequiresElapsedWindowAndCompletedProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.group.failureRecovery = 3 * time.Second
		check := func(err error) {
			d.applyCheck(checkResult{kind: checkSelection, generation: d.failures.generation, probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond, err: err}}})
		}
		check(errors.New("offline"))
		for range 10 {
			check(nil)
		}
		if !d.RuntimeStatus().Degraded {
			t.Fatal("rapid successes bypassed the time window")
		}
		time.Sleep(3 * time.Second)
		if !d.RuntimeStatus().Degraded {
			t.Fatal("time alone cleared degradation")
		}
		check(nil)
		if d.RuntimeStatus().Degraded {
			t.Fatal("endpoint success did not clear degradation")
		}
		check(errors.New("offline again"))
		check(nil)
		time.Sleep(2 * time.Second)
		check(errors.New("failed during recovery"))
		check(nil)
		time.Sleep(time.Second)
		check(nil)
		if status := d.RuntimeStatus(); !status.Degraded || status.RecoveryElapsed != time.Second {
			t.Fatalf("failure did not restart the window: %+v", status)
		}
	})
}

// startConfirmation models a reported failure whose confirmation has not run:
// the path keeps serving but is not alive for new selections.
func startConfirmation(d *Dialer) {
	d.ReportDataPlaneError(errors.New("upstream timeout"))
	d.mu.Lock()
	d.checks.pending &^= checkRequestDataPlane
	d.mu.Unlock()
}

func TestAliveCheckDoesNotProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}}})
		time.Sleep(time.Hour)
		began := time.Now()
		release, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
		if err != nil || time.Since(began) != 0 || d.connectivityCheckRequested() {
			t.Fatalf("an alive path was probed again: err=%v elapsed=%v", err, time.Since(began))
		}
		release()
	})
}

func TestHealthySelectionCheckKeepsConfiguredInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		prepareRecoveryDialer(d)
		c := testRecoveryChecker(t, d)
		flight := &selectionCheck{ctx: t.Context(), network: common.NetworkTCP4, done: make(chan struct{})}
		c.finishSelectionCheck(checkResult{
			kind:      checkSelection,
			request:   flight,
			attempted: true,
			probes:    []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}},
		})
		if flight.err != nil {
			t.Fatal(flight.err)
		}
		c.dispatch()
		if next := time.Until(c.healthAt); next != d.CheckInterval {
			t.Fatalf("next health check in %v; want %v", next, d.CheckInterval)
		}
	})
}

// A verification needs a representative result newer than the observation a
// group switched on. An in-flight probe provides one, repeated requests
// coalesce even while checks are paused, and a capability probe that leaves
// health unchanged does not answer it.
func TestVerificationNeedsOneRepresentativeResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		prepareRecoveryDialer(d)
		d.mu.Lock()
		d.health.networks[common.NetworkTCP6] = networkSupported // The representative network.
		d.mu.Unlock()
		var mu sync.Mutex
		var probed []common.NetworkIndex
		gate := make(chan struct{}, 2)
		checker := newConnectivityChecker(d.pathRuntime, func(_ context.Context, network *common.NetworkType) error {
			mu.Lock()
			probed = append(probed, network.Index())
			mu.Unlock()
			<-gate
			return nil
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		want := func(networks ...common.NetworkIndex) {
			t.Helper()
			synctest.Wait()
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(probed, networks) {
				t.Fatalf("probed %v, want %v", probed, networks)
			}
		}
		synctest.Wait()
		if d.RuntimeStatus().CheckEnabled {
			t.Fatal("test requires paused automatic checks")
		}
		want()

		d.RequestManualCheck()
		synctest.Wait()
		d.RequestVerification()
		gate <- struct{}{}
		want(common.NetworkTCP6)

		d.RequestVerification()
		d.RequestVerification()
		gate <- struct{}{}
		want(common.NetworkTCP6, common.NetworkTCP6)

		d.mu.Lock()
		d.health.networks[common.NetworkTCP4] = networkUntested
		d.mu.Unlock()
		var discovery sync.WaitGroup
		discovery.Go(func() {
			if release, err := d.Check(t.Context(), common.NetworkTCP4, time.Second); err == nil {
				release()
			}
		})
		synctest.Wait()
		d.RequestVerification()
		gate <- struct{}{}
		gate <- struct{}{}
		discovery.Wait()
		want(common.NetworkTCP6, common.NetworkTCP6, common.NetworkTCP4, common.NetworkTCP6)
	})
}

// Requests for different networks of one path do not wait for each other,
// even when one arrives while the other's probe runs.
func TestSelectionChecksOfDifferentNetworksRunConcurrently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, _ *common.NetworkType) error {
			select {
			case <-time.After(50 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		began := time.Now()
		var clients sync.WaitGroup
		for i, network := range []common.NetworkIndex{common.NetworkTCP6, common.NetworkTCP4} {
			arrival := time.Duration(i) * 10 * time.Millisecond
			clients.Go(func() {
				time.Sleep(arrival)
				release, err := d.Check(t.Context(), network, 80*time.Millisecond)
				if err != nil {
					t.Errorf("%v: %v after %v", network, err, time.Since(began))
					return
				}
				release()
				if elapsed := time.Since(began); elapsed != arrival+50*time.Millisecond {
					t.Errorf("%v answered after %v, want its own probe only", network, elapsed)
				}
			})
		}
		clients.Wait()
	})
}

// Closing a path while the run loop applies one selection result collects the
// others still running: synctest fails on a stranded sender.
func TestClosingPathCollectsConcurrentSelectionChecks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		group := &blockingGroup{entered: make(chan struct{}), release: make(chan struct{})}
		d.RegisterDialerGroup(group, DialerSelectionPolicy{}.WithDefaults())
		var probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, network *common.NetworkType) error {
			probes.Add(1)
			if network.L4Proto == consts.L4ProtoStr_TCP && network.IpVersion == consts.IpVersionStr_4 {
				time.Sleep(10 * time.Millisecond)
				return nil
			}
			<-ctx.Done()
			return ctx.Err()
		})
		start := make(chan struct{})
		close(start)
		var worker, clients sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		for _, network := range []common.NetworkIndex{common.NetworkTCP4, common.NetworkTCP6, common.NetworkUDP4} {
			clients.Go(func() {
				if release, err := d.Check(context.Background(), network, time.Minute); err == nil {
					release()
				}
			})
		}
		synctest.Wait()
		if started := probes.Load(); started != 3 {
			t.Fatalf("%d selection checks running, want 3", started)
		}
		// The TCP4 result notifies the group from inside finish.
		<-group.entered
		d.cancel()
		close(group.release)
		clients.Wait()
		worker.Wait()
		_ = d.Close()
	})
}

// blockingGroup holds its first notification until release.
type blockingGroup struct {
	once             sync.Once
	entered, release chan struct{}
}

func (g *blockingGroup) DialerChanged(*Dialer, SelectionForceMask) {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
}

// Connecting and the representative probe belong to the path: a sleeping path
// connects once and proves itself before discovery of another network runs,
// whichever request arrives first, so a hung discovery delays only its caller.
func TestSelectionChecksProveASleepingPathOnce(t *testing.T) {
	for _, order := range [][]common.NetworkIndex{{common.NetworkTCP4, common.NetworkTCP6}, {common.NetworkTCP6, common.NetworkTCP4}} {
		for _, hung := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/hung=%v", order, hung), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					d, err := NewRecreatableDialer(func() (*netproxy.Runtime, error) {
						return netproxy.NewRuntime(netproxy.Layer{Data: new(sleepingTestTransport)}), nil
					}, &GlobalOption{CheckInterval: time.Hour, CheckIntervalMax: time.Hour}, &Property{Name: t.Name()}, "")
					if err != nil {
						t.Fatal(err)
					}
					d.SetCheckEnabled(false)
					d.mu.Lock()
					d.health.networks[common.NetworkTCP6] = networkSupported // The representative network.
					d.mu.Unlock()
					var mu sync.Mutex
					var probed []common.NetworkIndex
					checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, network *common.NetworkType) error {
						mu.Lock()
						probed = append(probed, network.Index())
						mu.Unlock()
						if hung && network.Index() == common.NetworkTCP4 {
							<-ctx.Done()
							return ctx.Err()
						}
						select {
						case <-time.After(50 * time.Millisecond):
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					})
					start := make(chan struct{})
					close(start)
					var worker sync.WaitGroup
					worker.Go(func() { checker.run(start) })
					defer func() { _ = d.Close(); worker.Wait() }()
					began := time.Now()
					var clients sync.WaitGroup
					for i, network := range order {
						clients.Go(func() {
							time.Sleep(time.Duration(i) * time.Millisecond)
							release, err := d.Check(t.Context(), network, time.Second)
							if err == nil {
								release()
							}
							if hung && network == common.NetworkTCP4 {
								if err == nil {
									t.Errorf("hung discovery succeeded")
								}
								return
							}
							want := map[common.NetworkIndex]time.Duration{common.NetworkTCP6: 50 * time.Millisecond, common.NetworkTCP4: 100 * time.Millisecond}[network]
							if elapsed := time.Since(began); err != nil || elapsed != want {
								t.Errorf("%v: err=%v after %v, want success after %v", network, err, elapsed, want)
							}
						})
					}
					clients.Wait()
					d.mu.RLock()
					attempts := d.recovery.Attempt
					d.mu.RUnlock()
					mu.Lock()
					defer mu.Unlock()
					if !slices.Equal(probed, []common.NetworkIndex{common.NetworkTCP6, common.NetworkTCP4}) || attempts != 1 {
						t.Fatalf("probed %v with %d connection attempts, want the representative probe, then discovery after one connection", probed, attempts)
					}
				})
			})
		}
	}
}
