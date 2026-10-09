/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	log "github.com/sirupsen/logrus"
)

type checkKind uint8

const (
	checkInitial checkKind = iota
	checkHealth
	checkSupport
	checkCapacity
	checkSelection
)

var checkKindName = [...]string{"initial", "health", "support_retry", "capacity", "selection"}

type checkAttempt struct {
	kind       checkKind
	generation uint64
	reasons    checkRequestReason
}

type appliedCheck struct {
	success       bool
	healthApplied bool
}

// connectivityChecker owns scheduling and in-flight operations in its run loop.
// Shared demand and published progress live in pathRuntime.checks under mu.
type connectivityChecker struct {
	d       *pathRuntime
	probe   func(context.Context, *common.NetworkType) (bool, error)
	results chan checkResult
	flight  *selectionCheck

	runningKind      checkKind
	cancel           context.CancelFunc
	observedSeq      uint64
	blockedBy        string
	libraryRequested bool

	timer          *time.Timer
	healthAt       time.Time
	healthInterval time.Duration
	backingOff     bool
	staggerNext    bool

	supportAt     time.Time
	retryInterval time.Duration

	capacityInterval    time.Duration
	capacityAt          time.Time
	capacityBlockReason string
	capacityActive      bool
}

func newConnectivityChecker(d *pathRuntime, probe func(context.Context, *common.NetworkType) (bool, error)) *connectivityChecker {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	healthInterval := d.CheckInterval
	if healthInterval > 0 {
		healthInterval = time.Duration(fastrand.Int63n(int64(healthInterval)))
	}
	retryInterval := initialRetryInterval(d.CheckIntervalMax)
	return &connectivityChecker{
		d:              d,
		probe:          probe,
		results:        make(chan checkResult, 1),
		retryInterval:  retryInterval,
		healthInterval: healthInterval,
		timer:          timer,
	}
}

func (c *connectivityChecker) start(kind checkKind) {
	attempt := c.d.beginConnectivityCheck(kind)
	if attempt.reasons != 0 {
		c.blockedBy = ""
		c.libraryRequested = false
		kind = c.requestedCheckKind()
		attempt.kind = kind
		c.resetForRequest(attempt.reasons)
	}
	switch kind {
	case checkInitial, checkHealth:
		c.healthAt = time.Time{}
	case checkSupport:
		c.supportAt = time.Time{}
	case checkCapacity:
		c.capacityAt = time.Time{}
	}
	ctx, cancel := context.WithCancel(c.d.ctx)
	c.runningKind = kind
	c.cancel = cancel
	c.d.setRecovery(RecoveryQueued, time.Time{}, "connectivity_slot")
	go func() { c.results <- c.performAttempt(ctx, attempt) }()
}

func (c *connectivityChecker) handleSessionEvent(event netproxy.StateEvent) {
	c.observedSeq = max(c.observedSeq, event.Seq)
	advanced := c.d.applySessionState(event)
	// Recovery ownership can change while the dependency remains unready.
	if c.libraryRequested && event.RecoveryExecutor != netproxy.RecoveryLibraryManaged {
		c.libraryRequested = false
		advanced = true
	}
	needsRecovery := event.Accepting && !c.d.healthyAt(event.ReadinessVersion)
	if event.Accepting && event.RecoveryExecutor != netproxy.RecoveryLibraryManaged {
		if event.RecoveryRequired && !c.capacityActive {
			c.capacityActive = true
			c.d.mu.Lock()
			c.d.recovery.Attempt = 0
			c.d.statusRevision++
			c.d.mu.Unlock()
		}
		if !event.RecoveryRequired {
			c.capacityActive = false
			// A replacement can disappear before Connect's result is consumed.
			// Let finishCapacity validate the final capacity before clearing retry state.
			if c.cancel == nil || c.runningKind != checkCapacity {
				c.capacityAt = time.Time{}
				c.capacityInterval = 0
				c.capacityBlockReason = ""
			}
		}
	}
	if c.cancel != nil {
		if c.runningKind == checkSupport && (advanced || needsRecovery) {
			c.healthAt = time.Now()
		}
		return
	}
	if event.State == netproxy.SessionClosed {
		c.stopRetries()
		return
	}
	if c.blockedBy != "" {
		return
	}
	if event.RecoveryExecutor == netproxy.RecoveryLibraryManaged && !event.Accepting && c.libraryRequested {
		return
	}
	if event.State == netproxy.SessionConnected {
		if needsRecovery {
			c.resetHealthRetry()
			c.healthAt = time.Now()
		}
	} else if advanced {
		c.resetHealthRetry()
		c.healthAt = time.Now()
	}
}

func (c *connectivityChecker) drainSessionEvents(sessionEvents <-chan netproxy.StateEvent, seq uint64) <-chan netproxy.StateEvent {
	for sessionEvents != nil && c.observedSeq < seq {
		select {
		case event, ok := <-sessionEvents:
			if !ok {
				return nil
			}
			c.handleSessionEvent(event)
		case <-c.d.ctx.Done():
			return sessionEvents
		}
	}
	return sessionEvents
}

func (c *connectivityChecker) run(start <-chan struct{}) {
	select {
	case <-c.d.ctx.Done():
		return
	case <-start:
	}

	var sessionEvents <-chan netproxy.StateEvent
	if c.d.session != nil {
		sessionEvents = c.d.session.WatchState(c.d.ctx)
	}
	c.healthAt = time.Now()
	defer c.stopRetries()

	for {
		c.dispatch()
		select {
		case <-c.d.ctx.Done():
			if c.cancel != nil {
				c.cancel()
				<-c.results
			}
			return

		case event, ok := <-sessionEvents:
			if !ok {
				sessionEvents = nil
				continue
			}
			c.handleSessionEvent(event)

		case <-c.d.checks.wake:
			// The request flags survive until dispatch starts an operation.
		case <-c.timer.C:
			// Expired deadlines remain pending while an operation is running.

		case result := <-c.results:
			if c.d.session != nil {
				sessionEvents = c.drainSessionEvents(sessionEvents, result.seq)
			}
			if !c.finish(result) {
				return
			}
		}
	}
}

func (c *connectivityChecker) finish(result checkResult) bool {
	defer func() {
		c.d.mu.Lock()
		c.d.checks.running = false
		c.d.checks.probing = false
		if c.d.checks.paused {
			c.d.resetRecoveryObservationLocked()
		}
		c.d.updateTransportDemandLocked()
		if result.kind != checkCapacity {
			c.d.checks.checkedAt = time.Now()
		}
		c.d.statusRevision++
		c.d.mu.Unlock()
	}()
	if result.kind == checkSelection {
		c.finishSelectionCheck(result)
		c.cancel()
		c.cancel = nil
		return c.d.ctx.Err() == nil
	}
	c.cancel()
	c.cancel = nil
	if c.d.ctx.Err() != nil {
		return false
	}

	applied, ok := c.d.applyCheck(result)
	if result.kind == checkCapacity {
		c.finishCapacity(result, ok)
		return true
	}
	if reason := recoveryBlockedReason(result.failure()); reason != "" && ok && !applied.success {
		c.d.mu.Lock()
		c.d.failures.last = failureSnapshot(primaryNodeFailure(result.failure()), c.d.failures.generation)
		c.d.statusRevision++
		c.d.mu.Unlock()
		c.blockedBy = reason
		c.stopRetries()
		return true
	}
	if c.d.session != nil {
		snapshot := c.d.session.Snapshot()
		if snapshot.State == netproxy.SessionClosed {
			c.stopRetries()
			return true
		}
		if snapshot.RecoveryExecutor == netproxy.RecoveryLibraryManaged && !snapshot.Accepting {
			c.libraryRequested = true
			c.stopRetries()
			return true
		}
	}
	if ok {
		c.updateSchedule(result.kind, applied)
	} else {
		c.healthAt = time.Now()
	}
	return true
}

// Capacity work shares the checker's operation gate and global slots, but its
// failure never invalidates the health proof of still-serving sibling slots.
func (c *connectivityChecker) finishCapacity(result checkResult, applied bool) {
	snapshot := c.d.session.Snapshot()
	if !applied || !snapshot.Accepting {
		c.capacityAt = time.Time{}
		if snapshot.State == netproxy.SessionClosed {
			c.stopRetries()
		} else {
			c.healthAt = time.Now()
		}
		return
	}
	if reason := recoveryBlockedReason(result.connectErr); reason != "" {
		c.capacityBlockReason = reason
		return
	}
	if result.connectErr == nil && (!snapshot.RecoveryRequired || snapshot.UsableCapacity > result.capacityBefore) {
		c.capacityInterval = 0
		c.capacityAt = time.Time{}
		// Pooled transports may repair one slot per Connect. Continue only when
		// capacity actually survives; a nil error alone need not mean progress.
		// A new slot still needs an end-to-end proof before restoring health.
		if !c.d.healthyAt(snapshot.ReadinessVersion) {
			c.resetHealthRetry()
			c.healthAt = time.Now()
		}
		return
	}
	if result.connectErr != nil {
		log.WithField("node", c.d.name).WithError(result.connectErr).Debug("Outbound capacity replenishment failed; existing capacity remains usable")
	} else {
		log.WithField("node", c.d.name).Debug("Outbound capacity replenishment made no observable progress; retrying with backoff")
	}
	maximum := c.d.CheckIntervalMax
	if maximum <= 0 {
		maximum = time.Hour
	}
	if c.capacityInterval == 0 {
		c.capacityInterval = checkBackoffInitialInterval
	} else {
		c.capacityInterval = min(c.capacityInterval*2, maximum)
	}
	deadline := time.Now().Add(jitterRetryInterval(c.capacityInterval, maximum))
	c.capacityAt = deadline
}
