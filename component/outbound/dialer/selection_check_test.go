// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
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
				proof, err := d.Check(t.Context(), common.NetworkTCP4, timeout)
				defer proof.Release()
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) != 0 {
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
				proof, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
				defer proof.Release()
				if err != nil || !d.ProofValid(proof) {
					t.Errorf("proof=%+v err=%v", proof, err)
				}
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
			proof, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
			proof.Release()
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
			d.applyCheck(checkResult{kind: checkHealth, generation: d.failures.generation, probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond, err: err}}})
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

func TestHealthProofDoesNotReviveAfterRecovery(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed report", true: "confirmed outage"}[confirmed], func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			network := common.NetworkTCP4
			d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{{network: network, latency: time.Millisecond}}})
			before := d.SelectionSnapshot(network.NetworkType()).Proof
			if confirmed {
				d.applyCheck(checkResult{kind: checkHealth, probes: []probeResult{{network: network, err: errors.New("offline")}}})
			} else {
				d.ReportDataPlaneError(errors.New("upstream timeout"))
			}
			if d.ProofValid(before) {
				t.Fatal("failure did not invalidate the previous proof")
			}
			d.applyCheck(checkResult{kind: checkHealth, generation: d.failures.generation, probes: []probeResult{{network: network, latency: time.Millisecond}}})
			if !d.Usable(network.NetworkType()) {
				t.Fatal("successful confirmation did not recover the path")
			}
			if d.ProofValid(before) {
				t.Fatal("an old proof revived after recovery in the same Session")
			}
			if !d.ProofValid(d.SelectionSnapshot(network.NetworkType()).Proof) {
				t.Fatal("recovery did not produce a valid proof")
			}
		})
	}
}
