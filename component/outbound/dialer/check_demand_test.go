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
	"github.com/daeuniverse/outbound/netproxy"
)

func TestOnDemandCheckerDoesNotConnectOrRetryUntilRequested(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "healthy"}[healthy], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := newTestSessionTransport(netproxy.SessionDisconnected)
				d := newTestDialer(t, transport)
				d.SetCheckEnabled(false)
				var probes atomic.Int32
				release := make(chan struct{})
				checker := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, _ *common.NetworkType) (bool, error) {
					probes.Add(1)
					select {
					case <-release:
					case <-ctx.Done():
						return false, ctx.Err()
					}
					if !healthy {
						return false, errors.New("offline")
					}
					return true, nil
				})
				start := make(chan struct{})
				close(start)
				var workers sync.WaitGroup
				workers.Go(func() { checker.run(start) })
				defer func() { _ = d.Close(); workers.Wait() }()
				synctest.Wait()
				d.RequestConnectivityCheck() // Network changes must not wake dormant candidates.
				time.Sleep(2 * time.Hour)
				synctest.Wait()
				if probes.Load() != 0 || transport.connects.Load() != 0 || d.RuntimeStatus().Checking {
					t.Fatal("dormant node connected or probed automatically")
				}
				d.RequestManualCheck()
				synctest.Wait()
				if !d.RuntimeStatus().Checking || transport.connects.Load() != 1 {
					t.Fatal("manual test did not start the dormant transport")
				}
				for range 10 {
					d.RequestManualCheck()
				}
				close(release)
				synctest.Wait()
				status := d.RuntimeStatus()
				if status.Checking || status.CheckEnabled || status.CheckedAt.IsZero() || status.Healthy != healthy {
					t.Fatalf("one-shot result = %+v", status)
				}
				if probes.Load() != common.NetworkTypeCount {
					t.Fatalf("repeated requests were not coalesced: %d probes", probes.Load())
				}
				time.Sleep(2 * time.Hour)
				synctest.Wait()
				if probes.Load() != common.NetworkTypeCount {
					t.Fatal("one-shot test enabled periodic or failure retry work")
				}
				d.SetCheckEnabled(true)
				synctest.Wait()
				if probes.Load() <= common.NetworkTypeCount {
					t.Fatal("enabling tracking did not immediately check the node")
				}
				d.SetCheckEnabled(false)
				synctest.Wait()
				count := probes.Load()
				transport.state.Transition(netproxy.SessionDisconnected, errors.New("session lost"))
				time.Sleep(2 * time.Hour)
				synctest.Wait()
				if probes.Load() != count || transport.connects.Load() != 1 {
					t.Fatal("disabled tracking continued retrying after a session event")
				}
			})
		})
	}
}

func TestFailedConnectCompletesTestBeforeCapabilityDiscovery(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionDisconnected)
	transport.connectErr = errors.New("offline")
	d := newTestDialer(t, transport)
	checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) (bool, error) {
		t.Error("failed connection reached the probe")
		return false, nil
	})
	defer checker.stopRetries()
	checker.start(checkInitial)
	checker.finish(<-checker.results)
	status := d.RuntimeStatus()
	if status.Checking || status.CheckedAt.IsZero() || status.InitialCheckDone {
		t.Fatalf("failed connect must be testable again while capability is unknown: %+v", status)
	}
	d.RequestManualCheck()
	if !d.RuntimeStatus().Checking {
		t.Fatal("manual retry was not queued")
	}
}

func TestManualCheckSurvivesDeselection(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	prepareRecoveryDialer(d)
	checker := testRecoveryChecker(t, d)
	d.RequestConnectivityCheck()
	d.RequestManualCheck()
	d.SetCheckEnabled(false)
	checker.dispatch()
	if checker.cancel == nil {
		t.Fatal("deselection discarded the manual check with the automatic request")
	}
	finishCheck(checker, <-checker.results)
	status := d.RuntimeStatus()
	if status.CheckedAt.IsZero() || status.CheckEnabled || status.Checking {
		t.Fatalf("manual check did not finish as a one-shot probe: %+v", status)
	}
}

func TestManualCheckDuringCapacityReplenishment(t *testing.T) {
	transport := &testCapacityTransport{newTestSessionTransport(netproxy.SessionConnected)}
	event := transport.Snapshot()
	event.RecoveryRequired = true
	transport.state.Publish(event)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	var probes atomic.Int32
	checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) (bool, error) {
		probes.Add(1)
		return true, nil
	})
	t.Cleanup(checker.stopRetries)
	checker.start(checkCapacity)
	for range 10 {
		d.RequestManualCheck()
	}
	d.SetCheckEnabled(false)
	result := <-checker.results
	checker.handleSessionEvent(transport.Snapshot())
	finishCheck(checker, result)
	if checker.cancel == nil {
		t.Fatal("capacity replenishment discarded the manual connectivity check")
	}
	finishCheck(checker, <-checker.results)
	if status := d.RuntimeStatus(); probes.Load() != 1 || status.CheckedAt.IsZero() || status.Checking || status.CheckEnabled {
		t.Fatalf("manual requests did not produce exactly one probe: probes=%d status=%+v", probes.Load(), status)
	}
}

type retainedRecoveryTransport struct {
	*testSessionTransport
	offline atomic.Bool
}

func (transport *retainedRecoveryTransport) Connect(context.Context) error {
	transport.connects.Add(1)
	if transport.offline.Load() {
		return errors.New("offline")
	}
	transport.state.Transition(netproxy.SessionConnected, nil)
	return nil
}

func TestPausedRetainedDialerRecoversUntilReleased(t *testing.T) {
	for _, when := range []string{"before outage", "after outage"} {
		t.Run(when, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := &retainedRecoveryTransport{testSessionTransport: newTestSessionTransport(netproxy.SessionConnected)}
				d := newTestDialer(t, transport)
				prepareRecoveryDialer(d)
				d.SetCheckEnabled(false)
				var probes atomic.Int32
				checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) (bool, error) {
					probes.Add(1)
					return true, nil
				})
				start := make(chan struct{})
				close(start)
				var workers sync.WaitGroup
				workers.Go(func() { checker.run(start) })
				defer func() { _ = d.Close(); workers.Wait() }()
				synctest.Wait()

				var release func()
				retain := func() {
					var err error
					release, err = d.Retain()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(release)
					synctest.Wait()
				}
				if when == "before outage" {
					retain()
					if probes.Load() != 0 {
						t.Fatal("retaining a healthy paused node enabled automatic probes")
					}
				}
				transport.offline.Store(true)
				transport.state.Transition(netproxy.SessionDisconnected, errors.New("offline"))
				synctest.Wait()
				if when == "after outage" {
					retain()
				}
				if status := d.RuntimeStatus(); transport.connects.Load() != 1 || status.Recovery.RetryAt.IsZero() {
					t.Fatalf("retained node did not attempt recovery and schedule a retry: %+v", status)
				}
				transport.offline.Store(false)
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if status := d.RuntimeStatus(); !status.Healthy || status.CheckEnabled || transport.connects.Load() != 2 || probes.Load() != 1 {
					t.Fatalf("retained node did not reconnect and verify: %+v", status)
				}
				time.Sleep(2 * time.Hour)
				synctest.Wait()
				if probes.Load() != 1 {
					t.Fatal("recovery enabled periodic checks on the paused node")
				}

				transport.offline.Store(true)
				transport.state.Transition(netproxy.SessionDisconnected, errors.New("offline again"))
				synctest.Wait()
				release()
				synctest.Wait()
				attempts := transport.connects.Load()
				time.Sleep(2 * time.Hour)
				synctest.Wait()
				if transport.connects.Load() != attempts || !d.RuntimeStatus().Recovery.RetryAt.IsZero() {
					t.Fatal("recovery continued after the last retained caller released the node")
				}
			})
		})
	}
}
