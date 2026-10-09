/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common"
)

type checkRequestReason uint8

const (
	checkRequestDataPlane checkRequestReason = 1 << iota
	checkRequestEnvironment
	checkRequestManual
)

// pathChecks holds shared work demand and progress, protected by pathRuntime.mu.
// Pausing periodic checks does not discard manual or data-plane requests.
type pathChecks struct {
	wake         chan struct{}
	activated    bool
	paused       bool
	running      bool
	probing      bool
	checkedAt    time.Time
	pending      checkRequestReason
	activeProbes int
	selection    [common.NetworkTypeCount]*selectionCheck
}

func (d *pathRuntime) activateCheck(start <-chan struct{}) {
	d.mu.Lock()
	if d.checks.activated || d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	if !d.checksConnectivity && d.session == nil {
		d.checks.activated = true
		d.mu.Unlock()
		d.recordAvailability(true, false, time.Time{})
		return
	}
	d.checks.activated = true
	// Register the worker before releasing mu so Close cannot miss it.
	d.checkWG.Go(func() {
		newConnectivityChecker(d, d.checkDNSConnectivity).run(start)
	})
	d.mu.Unlock()
}

// RequestConnectivityCheck asks an automatically monitored checker to run soon.
// Requests that arrive during a check are coalesced into one follow-up round.
func (d *pathRuntime) RequestConnectivityCheck() {
	d.mu.Lock()
	if d.ctx.Err() != nil || d.checks.paused || !d.checksConnectivity && d.session == nil {
		d.mu.Unlock()
		return
	}
	d.checks.pending |= checkRequestEnvironment
	d.mu.Unlock()
	d.signalConnectivityCheck()
}

// SetCheckEnabled controls automatic checks without retiring the transport or
// interrupting an in-flight check. Explicit tests and data-plane confirmations
// can still run once while automatic checking is paused.
func (d *Dialer) SetCheckEnabled(enabled bool) {
	d.setCheckEnabled(enabled, true)
}

// SetMonitoring adopts an already verified candidate without scheduling a
// redundant immediate probe or invalidating an in-flight capability check.
func (d *Dialer) SetMonitoring(enabled bool) {
	d.setCheckEnabled(enabled, false)
}

func (d *Dialer) setCheckEnabled(enabled, immediate bool) {
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil || d.checkEnabled == enabled {
		d.mu.Unlock()
		return
	}
	d.checkEnabled = enabled
	pending := d.checks.pending
	d.updateCheckDemandLocked()
	if !immediate && enabled && d.healthyLocked(d.sessionSnapshot()) {
		d.checks.pending = d.checks.pending&^checkRequestEnvironment | pending
	}
	d.statusRevision++
	d.mu.Unlock()
	d.signalConnectivityCheck()
}

// RequestManualCheck preserves explicit demand when automatic work is canceled.
// Only an actual probe can satisfy it; capacity replenishment cannot.
func (d *pathRuntime) RequestManualCheck() {
	d.mu.Lock()
	if d.ctx.Err() != nil || !d.checksConnectivity || d.checks.probing || d.checks.pending&checkRequestManual != 0 {
		d.mu.Unlock()
		return
	}
	d.checks.pending |= checkRequestManual
	d.statusRevision++
	d.mu.Unlock()
	d.signalConnectivityCheck()
}

func (d *pathRuntime) signalConnectivityCheck() {
	select {
	case <-d.ctx.Done():
	case d.checks.wake <- struct{}{}:
	default:
	}
}

func (d *pathRuntime) connectivityCheckRequested() bool {
	d.mu.RLock()
	requested := d.checks.pending != 0
	d.mu.RUnlock()
	return requested
}

func (d *pathRuntime) beginConnectivityCheck(kind checkKind) checkAttempt {
	d.mu.Lock()
	attempt := checkAttempt{
		kind:       kind,
		generation: d.failures.generation,
		reasons:    d.checks.pending,
	}
	d.checks.pending = 0
	d.checks.running = true
	// Explicit demand promotes capacity work to a probe in start.
	d.checks.probing = kind != checkCapacity || attempt.reasons != 0
	d.updateTransportDemandLocked()
	d.mu.Unlock()
	return attempt
}

// Any selected/tracked member keeps the shared worker enabled. Explicit checks
// and recovery for retained callers retain their separate one-shot demand.
func (d *pathRuntime) updateCheckDemandLocked() {
	defer d.updateTransportDemandLocked()
	enabled := false
	for member := range d.members {
		enabled = enabled || member.active && member.checkEnabled
	}
	if !enabled {
		d.resetRecoveryObservationLocked()
	}
	if d.checks.paused == !enabled {
		return
	}
	d.checks.paused = !enabled
	if enabled {
		d.checks.pending |= checkRequestEnvironment
	} else {
		d.checks.pending &^= checkRequestEnvironment
	}
	d.statusRevision++
}

// ActivateCheck attaches a prepared member to an already running path without
// publishing statistics or callbacks while its group is still being built.
func (d *Dialer) ActivateCheck(start <-chan struct{}) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	if !d.active {
		d.active = true
		if !d.health.measuredAt.IsZero() && d.group != nil {
			d.group.latency.record(d.health.lastLatency)
		}
		if d.initialCheckCompletedLocked() || !d.checks.checkedAt.IsZero() {
			d.recordMemberAvailability(d.healthyLocked(d.sessionSnapshot()), false, time.Time{})
		}
		d.updateCheckDemandLocked()
	}
	d.mu.Unlock()
	d.pathRuntime.activateCheck(start)
	d.signalConnectivityCheck()
}
