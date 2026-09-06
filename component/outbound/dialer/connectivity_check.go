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

const (
	checkBackoffInitialInterval = time.Second
	supportRetryInitialInterval = time.Second
	supportRetryMultiplier      = 4
)

func (d *Dialer) ActivateCheck(start <-chan struct{}) {
	d.mu.Lock()
	if d.checkActivated || d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	if !d.checksConnectivity && d.session == nil {
		d.checkActivated = true
		d.mu.Unlock()
		d.recordAvailability(true, false, time.Time{})
		return
	}
	if d.group == nil && d.checksConnectivity {
		d.mu.Unlock()
		return
	}
	d.checkActivated = true
	d.checkWG.Add(1)
	d.mu.Unlock()

	checker := newConnectivityChecker(d, d.checkDNSConnectivity)
	go func() {
		defer d.checkWG.Done()
		checker.run(start)
	}()
}

// RequestConnectivityCheck asks the checker to run as soon as practical.
// Requests that arrive during a check are coalesced into one follow-up round.
func (d *Dialer) RequestConnectivityCheck() {
	d.mu.Lock()
	if d.ctx.Err() != nil || !d.checksConnectivity && d.session == nil {
		d.mu.Unlock()
		return
	}
	d.pendingCheck |= checkRequestEnvironment
	d.mu.Unlock()
	d.signalConnectivityCheck()
}

func (d *Dialer) signalConnectivityCheck() {
	select {
	case <-d.ctx.Done():
	case d.checkCh <- struct{}{}:
	default:
	}
}

func (d *Dialer) connectivityCheckRequested() bool {
	d.mu.RLock()
	requested := d.pendingCheck != 0
	d.mu.RUnlock()
	return requested
}

func (d *Dialer) beginConnectivityCheck(kind checkKind) checkAttempt {
	d.mu.Lock()
	attempt := checkAttempt{
		kind:       kind,
		generation: d.failureGeneration,
		reasons:    d.pendingCheck,
	}
	d.pendingCheck = 0
	d.mu.Unlock()
	return attempt
}

func jitterCheckInterval(interval time.Duration) time.Duration {
	spread := interval / 5
	if spread <= 0 {
		return interval
	}
	return interval - spread + time.Duration(fastrand.Int63n(int64(2*spread+1)))
}

type checkKind uint8

const (
	checkInitial checkKind = iota
	checkHealth
	checkSupport
	checkCapacity
)

var checkKindName = [...]string{"initial", "health", "support_retry", "capacity"}

type checkAttempt struct {
	kind       checkKind
	generation uint64
	reasons    checkRequestReason
}

type appliedCheck struct {
	success       bool
	healthApplied bool
}

type connectivityChecker struct {
	d       *Dialer
	probe   func(context.Context, *common.NetworkType) (bool, error)
	results chan checkResult

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

func newConnectivityChecker(d *Dialer, probe func(context.Context, *common.NetworkType) (bool, error)) *connectivityChecker {
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

func (c *connectivityChecker) scheduleSupport() {
	if !c.supportPending() {
		c.supportAt = time.Time{}
		return
	}
	if c.supportAt.IsZero() {
		deadline := time.Now().Add(jitterRetryInterval(c.retryInterval, c.d.CheckIntervalMax))
		c.supportAt = deadline
		c.retryInterval = nextRetryInterval(c.retryInterval, c.d.CheckIntervalMax)
	}
}

func (c *connectivityChecker) requestedCheckKind() checkKind {
	if !c.d.initialCheckCompleted() {
		return checkInitial
	}
	if firstSupportedNetwork(c.d.networkStates()).Valid() {
		return checkHealth
	}
	return checkSupport
}

func (c *connectivityChecker) resetForRequest(reasons checkRequestReason) {
	if reasons&checkRequestEnvironment != 0 {
		c.capacityBlockReason = ""
		c.capacityInterval = 0
		c.capacityAt = time.Time{}
		c.retryInterval = initialRetryInterval(c.d.CheckIntervalMax)
		c.supportAt = time.Time{}
	}
	if reasons&(checkRequestEnvironment|checkRequestDataPlane) != 0 {
		c.resetHealthRetry()
	}
}

func (c *connectivityChecker) resetHealthRetry() {
	c.healthInterval = c.d.CheckInterval
	c.backingOff = false
	c.staggerNext = true
	c.healthAt = time.Time{}
}

func (c *connectivityChecker) handleSessionEvent(event netproxy.StateEvent) {
	c.observedSeq = max(c.observedSeq, event.Seq)
	advanced := c.d.applySessionState(event)
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
			c.capacityAt = time.Time{}
			c.capacityInterval = 0
			c.capacityBlockReason = ""
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

		case <-c.d.checkCh:
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

// Discard scheduled work when the lifecycle stops or retrying is blocked.
func (c *connectivityChecker) stopRetries() {
	c.timer.Stop()
	c.healthAt, c.supportAt, c.capacityAt = time.Time{}, time.Time{}, time.Time{}
}

func (c *connectivityChecker) finish(result checkResult) bool {
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
	if reason := recoveryBlockedReason(result.connectErr); reason != "" && ok {
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
	if c.d.session == nil {
		return
	}
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
	if result.connectErr == nil && !snapshot.RecoveryRequired {
		c.capacityInterval = 0
		return
	}
	if result.connectErr != nil {
		log.WithField("node", c.d.Name).WithError(result.connectErr).Debug("Outbound capacity replenishment failed; existing capacity remains usable")
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

func (c *connectivityChecker) updateSchedule(kind checkKind, applied appliedCheck) {
	if !c.d.checksConnectivity {
		if applied.success {
			c.healthAt = time.Time{}
		} else {
			c.updateHealthSchedule(false)
		}
		return
	}
	switch kind {
	case checkInitial:
		c.updateInitialSchedule(applied.success)
	case checkHealth:
		c.updateHealthSchedule(applied.success)
	case checkSupport:
		if applied.healthApplied {
			c.healthAt = time.Time{}
			c.updateHealthSchedule(true)
		}
	}
	c.scheduleSupport()
}

func (c *connectivityChecker) updateInitialSchedule(success bool) {
	if !c.d.initialCheckCompleted() {
		c.healthAt = time.Now().Add(jitterRetryInterval(c.retryInterval, c.d.CheckIntervalMax))
		c.retryInterval = nextRetryInterval(c.retryInterval, c.d.CheckIntervalMax)
		return
	}
	c.retryInterval = initialRetryInterval(c.d.CheckIntervalMax)
	if !success {
		if !c.supportPending() && !firstSupportedNetwork(c.d.networkStates()).Valid() {
			c.blockedBy = "no_supported_network"
		}
		return
	}
	delay := c.healthInterval
	c.healthInterval = c.d.CheckInterval
	c.backingOff = false
	if c.staggerNext {
		delay = jitterCheckInterval(c.healthInterval)
		c.staggerNext = false
	}
	c.healthAt = time.Now().Add(delay)
}

func (c *connectivityChecker) updateHealthSchedule(success bool) {
	maximum := c.d.CheckIntervalMax
	if maximum <= 0 {
		maximum = time.Hour
	}
	if success {
		c.healthInterval = c.d.CheckInterval
		c.backingOff = false
	} else if c.backingOff {
		c.healthInterval = min(c.healthInterval*2, maximum)
	} else {
		c.healthInterval = checkBackoffInitialInterval
		c.backingOff = true
	}
	delay := c.healthInterval
	if !success {
		delay = jitterRetryInterval(delay, maximum)
	} else if c.staggerNext {
		delay = jitterCheckInterval(delay)
		c.staggerNext = false
	}
	c.healthAt = time.Now().Add(delay)
}

// dispatch is the only scheduler entry point. Event handlers update facts and
// deadlines; here we choose one operation or arm the single wake-up timer.
func (c *connectivityChecker) dispatch() {
	c.timer.Stop()
	if c.cancel != nil || c.d.ctx.Err() != nil {
		return
	}
	status := c.d.RuntimeStatus()
	if c.d.session != nil && status.Session.State == netproxy.SessionClosed {
		c.stopRetries()
		c.d.setRecovery(RecoveryStopped, time.Time{}, "")
		return
	}
	if c.d.connectivityCheckRequested() {
		c.start(c.requestedCheckKind())
		return
	}
	if c.blockedBy != "" {
		c.d.setRecovery(RecoveryBlocked, time.Time{}, c.blockedBy)
		return
	}
	if c.libraryRequested && status.Session.RecoveryExecutor == netproxy.RecoveryLibraryManaged && !status.Session.Accepting {
		c.d.setRecovery(RecoveryConnecting, time.Time{}, "protocol_recovery")
		return
	}

	now := time.Now()
	needsCapacity := status.Healthy && status.Session.RecoveryRequired &&
		status.Session.RecoveryExecutor != netproxy.RecoveryLibraryManaged
	capacityAt := c.capacityAt
	if !needsCapacity || c.capacityBlockReason != "" {
		capacityAt = time.Time{}
	} else if capacityAt.IsZero() {
		capacityAt = now
	}

	// Due health work takes priority over replenishment and capability discovery.
	if !c.healthAt.IsZero() && !c.healthAt.After(now) {
		c.healthAt = time.Time{}
		c.start(c.requestedCheckKind())
		return
	}
	if !capacityAt.IsZero() && !capacityAt.After(now) {
		c.start(checkCapacity)
		return
	}
	if !c.supportAt.IsZero() && !c.supportAt.After(now) {
		c.start(checkSupport)
		return
	}

	// Otherwise sleep until the earliest deadline; zero means unscheduled.
	var next time.Time
	for _, deadline := range [...]time.Time{c.healthAt, capacityAt, c.supportAt} {
		if !deadline.IsZero() && (next.IsZero() || deadline.Before(next)) {
			next = deadline
		}
	}
	if !next.IsZero() {
		c.timer.Reset(time.Until(next))
	}
	// Publish waiting status from the same deadlines that drive the timer.
	// In-flight status is published by connect/probe operations themselves.
	switch {
	case needsCapacity && c.capacityBlockReason != "":
		c.d.updateRecovery(RecoveryBlocked, time.Time{}, c.capacityBlockReason, "replenish")
	case needsCapacity && !capacityAt.IsZero():
		c.d.updateRecovery(RecoveryBackoff, capacityAt, "capacity", "replenish")
	case !status.Healthy && !next.IsZero():
		c.d.setRecovery(RecoveryBackoff, next, "")
	default:
		c.d.setRecovery(RecoveryReady, time.Time{}, "")
	}
}

func nextRetryInterval(interval, maximum time.Duration) time.Duration {
	if maximum <= 0 {
		maximum = supportRetryInitialInterval
	}
	if interval >= maximum/time.Duration(supportRetryMultiplier) {
		return maximum
	}
	return min(interval*time.Duration(supportRetryMultiplier), maximum)
}

func initialRetryInterval(maximum time.Duration) time.Duration {
	if maximum > 0 {
		return min(supportRetryInitialInterval, maximum)
	}
	return supportRetryInitialInterval
}

func jitterRetryInterval(interval, maximum time.Duration) time.Duration {
	low, high := retryJitterRange(interval, maximum)
	if low == high {
		return low
	}
	return low + time.Duration(fastrand.Int63n(int64(high-low+1)))
}

func retryJitterRange(interval, maximum time.Duration) (low, high time.Duration) {
	spread := interval / 5
	if spread <= 0 {
		return interval, interval
	}
	low = interval - spread
	high = interval + spread
	if maximum > 0 {
		high = min(high, maximum)
	}
	return low, high
}

func (c *connectivityChecker) supportPending() bool {
	pending := false
	for _, state := range c.d.networkStates() {
		if state == networkUntested {
			return false
		}
		if state == networkUnknown {
			pending = true
		}
	}
	return pending
}
