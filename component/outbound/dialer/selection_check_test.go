// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
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

// A verification needs a representative result newer than the observation a
// group switched on. The serial worker makes an in-flight probe one, repeated
// requests coalesce even while checks are paused, and a capability probe that
// leaves health unchanged does not answer it.
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
