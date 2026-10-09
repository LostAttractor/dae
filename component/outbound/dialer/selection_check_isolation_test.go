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

func TestQueuedProofVerifiesItsOwnNetwork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
			{network: common.NetworkTCP4, latency: time.Millisecond},
			{network: common.NetworkTCP6, latency: time.Millisecond},
		}})
		time.Sleep(time.Second)
		var ipv6Probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, network *common.NetworkType) (bool, error) {
			if network.Index() == common.NetworkTCP6 {
				ipv6Probes.Add(1)
				return false, errors.New("IPv6 egress became unreachable")
			}
			select {
			case <-time.After(50 * time.Millisecond):
				return true, nil
			case <-ctx.Done():
				return false, ctx.Err()
			}
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		ipv4 := make(chan error, 1)
		go func() {
			proof, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
			proof.Release()
			ipv4 <- err
		}()
		synctest.Wait()
		proof, err := d.Check(t.Context(), common.NetworkTCP6, time.Second)
		defer proof.Release()
		if first := <-ipv4; first != nil {
			t.Fatalf("healthy IPv4 check failed: %v", first)
		}
		if err == nil || ipv6Probes.Load() == 0 {
			t.Fatalf("unverified broken IPv6 returned a proof: err=%v valid=%v IPv6 probes=%d", err, d.ProofValid(proof), ipv6Probes.Load())
		}
	})
}

func TestFirstShortWaiterDoesNotTruncateLongWaiter(t *testing.T) {
	for _, response := range []time.Duration{50 * time.Millisecond, time.Hour} {
		t.Run(response.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newTestDialer(t, testTransport{})
				d.SetCheckEnabled(false)
				d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond}}})
				time.Sleep(time.Second)
				checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, _ *common.NetworkType) (bool, error) {
					select {
					case <-time.After(response):
						return true, nil
					case <-ctx.Done():
						return false, ctx.Err()
					}
				})
				start := make(chan struct{})
				close(start)
				var worker sync.WaitGroup
				worker.Go(func() { checker.run(start) })
				defer func() { _ = d.Close(); worker.Wait() }()
				short := make(chan error, 1)
				go func() {
					proof, err := d.Check(t.Context(), common.NetworkTCP4, 10*time.Millisecond)
					proof.Release()
					short <- err
				}()
				synctest.Wait()
				began := time.Now()
				proof, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
				defer proof.Release()
				if shortErr := <-short; !errors.Is(shortErr, context.DeadlineExceeded) {
					t.Fatalf("short waiter did not respect its own budget: %v", shortErr)
				}
				if response < time.Second {
					if err != nil || !d.ProofValid(proof) || time.Since(began) >= time.Second {
						t.Fatalf("long waiter lost its own budget: err=%v elapsed=%v", err, time.Since(began))
					}
				} else if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) != time.Second {
					t.Fatalf("retry reset the caller's budget: err=%v elapsed=%v", err, time.Since(began))
				}
			})
		})
	}
}

func TestSelectionCheckDoesNotRetryTargetTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.SetCheckEnabled(false)
		var probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) (bool, error) {
			probes.Add(1)
			time.Sleep(time.Millisecond)
			return false, context.DeadlineExceeded
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		began := time.Now()
		_, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
		if !errors.Is(err, context.DeadlineExceeded) || probes.Load() != 1 || time.Since(began) != time.Millisecond {
			t.Fatalf("target timeout retried as a shorter shared deadline: err=%v probes=%d elapsed=%v", err, probes.Load(), time.Since(began))
		}
	})
}

func TestHealthProofKeepsItsNetworkAndFailureGeneration(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
		{network: common.NetworkTCP4}, {network: common.NetworkTCP6},
	}})
	before6 := d.SelectionSnapshot(common.NetworkTCP6.NetworkType()).Proof
	d.applyCheck(checkResult{kind: checkHealth, probes: []probeResult{{network: common.NetworkTCP4}}})
	after6 := d.SelectionSnapshot(common.NetworkTCP6.NetworkType()).Proof
	if !before6.SameObservation(after6) {
		t.Fatal("a TCP4 result refreshed the TCP6 observation")
	}
	d.ReportDataPlaneError(errors.New("path failed"))
	if !d.VerifiedUsable(common.NetworkTCP6.NetworkType()) {
		t.Fatal("failure confirmation prematurely withdrew an admitted path")
	}
	d.applyCheck(checkResult{kind: checkSelection, generation: d.failures.generation, probes: []probeResult{{network: common.NetworkTCP4}}})
	if !d.ProofValid(d.SelectionSnapshot(common.NetworkTCP4.NetworkType()).Proof) ||
		d.ProofValid(d.SelectionSnapshot(common.NetworkTCP6.NetworkType()).Proof) {
		t.Fatal("TCP4 recovery revived an unverified TCP6 proof from before the failure")
	}
	if !d.VerifiedUsable(common.NetworkTCP4.NetworkType()) || d.VerifiedUsable(common.NetworkTCP6.NetworkType()) {
		t.Fatal("an already selected TCP6 path resumed without its own new proof")
	}
}
