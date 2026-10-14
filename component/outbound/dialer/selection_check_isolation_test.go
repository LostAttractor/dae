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
)

func TestKnownCapabilitiesShareSelectionProbe(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint("failed=", failed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newTestDialer(t, testTransport{})
				d.SetCheckEnabled(false)
				var initial []probeResult
				for network := range common.NetworkIndex(common.NetworkTypeCount) {
					initial = append(initial, probeResult{network: network})
				}
				d.applyCheck(checkResult{kind: checkInitial, probes: initial})
				time.Sleep(time.Second)
				var probes [common.NetworkTypeCount]atomic.Int32
				probeErr := errors.New("representative probe failed")
				checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, network *common.NetworkType) error {
					probes[network.Index()].Add(1)
					select {
					case <-time.After(50 * time.Millisecond):
						if failed {
							return probeErr
						}
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
				var proofs [common.NetworkTypeCount]HealthProof
				for network := range common.NetworkIndex(common.NetworkTypeCount) {
					clients.Go(func() {
						proof, err := d.Check(t.Context(), network, time.Second)
						defer proof.Release()
						proofs[network] = proof
						if failed {
							if !errors.Is(err, probeErr) {
								t.Errorf("%v: %v", network, err)
							}
						} else if err != nil || proof.Network != network || !d.ProofValid(proof) {
							t.Errorf("%v: proof=%+v err=%v", network, proof, err)
						}
					})
				}
				clients.Wait()
				synctest.Wait()
				for network := range common.NetworkIndex(common.NetworkTypeCount) {
					want := int32(0)
					if network == common.NetworkTCP6 {
						want = 1
					}
					if failed {
						want++ // One new discovery sweep after the shared failure.
					}
					if probes[network].Load() != want {
						t.Errorf("%v probes=%d want=%d", network, probes[network].Load(), want)
					}
					if !failed && !proofs[network].SameObservation(proofs[common.NetworkTCP6]) {
						t.Errorf("%v has a separate observation", network)
					}
				}
			})
		})
	}
}

func TestFirstShortWaiterDoesNotTruncateLongWaiter(t *testing.T) {
	for _, response := range []time.Duration{50 * time.Millisecond, time.Hour} {
		t.Run(response.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newTestDialer(t, testTransport{})
				d.SetCheckEnabled(false)
				d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
					{network: common.NetworkTCP4, latency: time.Millisecond},
					{network: common.NetworkTCP6, latency: time.Millisecond},
				}})
				time.Sleep(time.Second)
				checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, _ *common.NetworkType) error {
					select {
					case <-time.After(response):
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
				short := make(chan error, 1)
				go func() {
					proof, err := d.Check(t.Context(), common.NetworkTCP4, 10*time.Millisecond)
					proof.Release()
					short <- err
				}()
				synctest.Wait()
				began := time.Now()
				proof, err := d.Check(t.Context(), common.NetworkTCP6, time.Second)
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
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
			probes.Add(1)
			time.Sleep(time.Millisecond)
			return context.DeadlineExceeded
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

func TestSharedHealthProofInvalidatedAcrossCapabilities(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{
		{network: common.NetworkTCP4}, {network: common.NetworkTCP6},
	}})
	before := d.SelectionSnapshot(common.NetworkTCP4.NetworkType()).Proof
	d.ReportDataPlaneError(errors.New("path failed"))
	for _, network := range []common.NetworkIndex{common.NetworkTCP4, common.NetworkTCP6} {
		if !d.VerifiedUsable(network.NetworkType()) || d.ProofValid(d.SelectionSnapshot(network.NetworkType()).Proof) {
			t.Fatalf("%v: confirmation must retain admission while invalidating proofs for new selections", network)
		}
	}
	d.applyCheck(checkResult{kind: checkSelection, generation: d.failures.generation, probes: []probeResult{{network: common.NetworkTCP6}}})
	if d.ProofValid(before) {
		t.Fatal("old proof revived after recovery")
	}
	for _, network := range []common.NetworkIndex{common.NetworkTCP4, common.NetworkTCP6} {
		proof := d.SelectionSnapshot(network.NetworkType()).Proof
		if !d.ProofValid(proof) || !d.VerifiedUsable(network.NetworkType()) || before.SameObservation(proof) {
			t.Fatalf("%v did not receive the new shared observation", network)
		}
	}
	if d.ProofValid(d.SelectionSnapshot(common.NetworkUDP4.NetworkType()).Proof) {
		t.Fatal("shared health fabricated an unknown capability")
	}
}

func TestSelectionDiscoveryReusesOnlyFreshRepresentativeProof(t *testing.T) {
	for _, tc := range []struct {
		name             string
		known, requested common.NetworkIndex
		fresh            bool
		want             []common.NetworkIndex
		latency          time.Duration
	}{
		{"fresh", common.NetworkTCP6, common.NetworkTCP4, true, []common.NetworkIndex{common.NetworkTCP4}, 5 * time.Millisecond},
		{"stale", common.NetworkTCP6, common.NetworkTCP4, false, []common.NetworkIndex{common.NetworkTCP4, common.NetworkTCP6}, 2 * time.Millisecond},
		{"new representative", common.NetworkTCP4, common.NetworkTCP6, false, []common.NetworkIndex{common.NetworkTCP6}, time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newTestDialer(t, testTransport{})
				d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{{network: tc.known, latency: 5 * time.Millisecond}}})
				before := d.SelectionSnapshot(tc.known.NetworkType()).Proof
				if !tc.fresh {
					time.Sleep(time.Second)
				}
				var probes []common.NetworkIndex
				checker := newConnectivityChecker(d.pathRuntime, func(_ context.Context, network *common.NetworkType) error {
					probes = append(probes, network.Index())
					time.Sleep(time.Duration(len(probes)) * time.Millisecond)
					return nil
				})
				defer checker.stopRetries()
				result := checker.performSelectionCheck(&selectionCheck{ctx: t.Context(), network: tc.requested, requestedAt: time.Now()}, d.failures.generation)
				applied, ok := d.applyCheck(result)
				proof := d.SelectionSnapshot(tc.requested.NetworkType()).Proof
				if !ok || !applied.success || !d.ProofValid(proof) || !slices.Equal(probes, tc.want) {
					t.Fatalf("discovery probes=%v want=%v applied=%+v proof=%+v", probes, tc.want, applied, proof)
				}
				if proof.SameObservation(before) != tc.fresh || d.RuntimeStatus().Latency.Last != tc.latency {
					t.Fatalf("capability discovery changed the wrong health observation: proof=%+v latency=%v", proof, d.RuntimeStatus().Latency.Last)
				}
			})
		})
	}
}
