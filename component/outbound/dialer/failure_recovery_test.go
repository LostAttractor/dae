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

func TestDefaultRecoveryWindowOverridesThreeMinuteChecks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.CheckInterval = 3 * time.Minute
		prepareRecoveryDialer(d)
		d.applyCheck(checkResult{kind: checkHealth, probes: []probeResult{{network: common.NetworkTCP4, err: errors.New("offline")}}})
		var probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
			probes.Add(1)
			return nil
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		synctest.Wait()
		if status := d.RuntimeStatus(); !status.Healthy || !status.Degraded || status.FailureRecovery != 30*time.Second {
			t.Fatalf("first success did not start the default recovery window: %+v", status)
		}
		if recovery := d.RuntimeStatus().Recovery; recovery.Phase != RecoveryBackoff || recovery.Action != "verify" || !recovery.RetryAt.Equal(time.Now().Add(5*time.Second)) {
			t.Fatalf("recovery observation did not publish its next probe: %+v", recovery)
		}
		time.Sleep(29 * time.Second)
		synctest.Wait()
		if probes.Load() != 6 || !d.RuntimeStatus().Degraded {
			t.Fatalf("recovery did not check at 0/5/10/15/20/25 seconds: probes=%d", probes.Load())
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if probes.Load() != 7 || d.RuntimeStatus().Degraded {
			t.Fatalf("30-second endpoint verification did not complete recovery: probes=%d", probes.Load())
		}
		if recovery := d.RuntimeStatus().Recovery; recovery.Phase != RecoveryReady || !recovery.RetryAt.IsZero() {
			t.Fatalf("completed observation still advertised a recovery check: %+v", recovery)
		}
	})
}

func TestRecoveryStatusWhileProbeTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		prepareRecoveryDialer(d)
		d.applyCheck(checkResult{kind: checkHealth, probes: []probeResult{{network: common.NetworkTCP4, err: errors.New("offline")}}})
		var probes atomic.Int32
		checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, _ *common.NetworkType) error {
			if probes.Add(1) == 1 {
				return nil
			}
			<-ctx.Done()
			return ctx.Err()
		})
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		synctest.Wait()
		first := d.RuntimeStatus()
		if !first.Healthy || !first.Degraded || first.RecoveryElapsed != 0 || first.Recovery.RetryAt.IsZero() {
			t.Fatalf("first success did not publish recovery observation: %+v", first)
		}
		time.Sleep(time.Until(first.Recovery.RetryAt))
		synctest.Wait()
		checking := d.RuntimeStatus()
		if probes.Load() != 2 || !checking.Healthy || !checking.Checking || checking.RecoveryElapsed != 0 || checking.Recovery.Phase != RecoveryVerifying || !checking.Recovery.RetryAt.IsZero() {
			t.Fatalf("pending probe was hidden behind zero recovery progress: %+v", checking)
		}
		time.Sleep(d.group.probeTimeout)
		synctest.Wait()
		failed := d.RuntimeStatus()
		if failed.Healthy || !failed.Degraded || failed.RecoveryElapsed != 0 || failed.Recovery.Phase != RecoveryBackoff || !failed.Recovery.RetryAt.After(time.Now()) {
			t.Fatalf("timed-out observation did not publish failure and its next check: %+v", failed)
		}
	})
}

func TestRecoverySharesObservationButKeepsGroupDurations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		other := shareTestDialer(t, d)
		d.group.failureRecovery = time.Second
		other.group.failureRecovery = 3 * time.Second
		check := func(err error) {
			d.applyCheck(checkResult{kind: checkHealth, generation: d.failures.generation, probes: []probeResult{{network: common.NetworkTCP4, err: err}}})
		}
		check(errors.New("offline"))
		check(nil)
		time.Sleep(time.Second)
		check(nil)
		if d.RuntimeStatus().Degraded || !other.RuntimeStatus().Degraded {
			t.Fatal("shared groups ignored their observation durations")
		}
		// Pausing interrupts the unfinished window, preserving completed ones.
		d.SetMonitoring(false)
		other.SetMonitoring(false)
		time.Sleep(time.Hour)
		check(nil)
		if d.RuntimeStatus().Degraded || !other.RuntimeStatus().Degraded || other.RuntimeStatus().RecoveryElapsed != 0 {
			t.Fatal("idle time counted toward recovery, or a completed window was lost")
		}
		time.Sleep(3 * time.Second)
		check(nil)
		if other.RuntimeStatus().Degraded {
			t.Fatal("shared probe did not complete the longer window")
		}
		check(errors.New("offline again"))
		if !d.RuntimeStatus().Degraded || !other.RuntimeStatus().Degraded {
			t.Fatal("new failure did not reset all groups")
		}
	})
}

func TestUnconfirmedSampleDoesNotAdvanceRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newTestDialer(t, testTransport{})
		d.health.networks[common.NetworkTCP4] = networkSupported
		check := func(generation uint64, err error) {
			d.applyCheck(checkResult{kind: checkHealth, generation: generation,
				probes: []probeResult{{network: common.NetworkTCP4, latency: time.Millisecond, err: err}}})
		}
		check(d.failures.generation, errors.New("offline"))
		check(d.failures.generation, nil)
		before := d.RuntimeStatus()
		generation := d.failures.generation
		d.ReportDataPlaneError(errors.New("new upstream failure"))
		time.Sleep(time.Second)
		check(generation, nil) // A sample from a check started before the report.
		after := d.RuntimeStatus()
		if !after.MeasuredAt.After(before.MeasuredAt) {
			t.Fatal("successful latency sample was lost")
		}
		if !after.ConfirmingFailure || after.RecoveryElapsed != before.RecoveryElapsed {
			t.Fatal("a stale success advanced recovery before failure confirmation completed")
		}
	})
}
