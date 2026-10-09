/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

const (
	checkBackoffInitialInterval = time.Second
	supportRetryInitialInterval = time.Second
	supportRetryMultiplier      = 4
)

func jitterCheckInterval(interval time.Duration) time.Duration {
	spread := interval / 5
	if spread <= 0 {
		return interval
	}
	return interval - spread + time.Duration(fastrand.Int63n(int64(2*spread+1)))
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
	if reasons&(checkRequestEnvironment|checkRequestManual) != 0 {
		c.capacityBlockReason = ""
		c.capacityInterval = 0
		c.capacityAt = time.Time{}
		c.retryInterval = initialRetryInterval(c.d.CheckIntervalMax)
		c.supportAt = time.Time{}
	}
	if reasons&(checkRequestEnvironment|checkRequestManual|checkRequestDataPlane) != 0 {
		c.resetHealthRetry()
	}
}

func (c *connectivityChecker) resetHealthRetry() {
	c.healthInterval = c.d.CheckInterval
	c.backingOff = false
	c.staggerNext = true
	c.healthAt = time.Time{}
}

// Discard scheduled work when the lifecycle stops or retrying is blocked.
func (c *connectivityChecker) stopRetries() {
	c.timer.Stop()
	c.healthAt, c.supportAt, c.capacityAt = time.Time{}, time.Time{}, time.Time{}
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
	status := c.d.runtimeStatus()
	if c.d.session != nil && status.Session.State == netproxy.SessionClosed {
		c.stopRetries()
		c.d.setRecovery(RecoveryStopped, time.Time{}, "")
		return
	}
	if c.d.connectivityCheckRequested() {
		c.start(c.requestedCheckKind())
		return
	}
	if c.startSelectionCheck() {
		return
	}
	if !status.CheckEnabled {
		c.d.mu.RLock()
		demand := c.d.retains > 0
		for member := range c.d.members {
			demand = demand || member.selected && !member.closed
		}
		c.d.mu.RUnlock()
		if !demand || !status.HasSession || status.Healthy && !status.Session.RecoveryRequired {
			c.stopRetries()
			c.d.setRecovery(RecoveryReady, time.Time{}, "")
			return
		}
		// Selected failover paths and retained callers still need capacity.
		// Repair it without enabling periodic latency or capability discovery.
		c.supportAt = time.Time{}
		if status.Healthy {
			c.healthAt = time.Time{}
		} else if c.healthAt.IsZero() {
			c.healthAt = time.Now()
		}
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
	recoveryAt, recoveryTimeout := c.d.recoveryCheckPlan()
	if recoveryTimeout > 0 {
		if recoveryAt.IsZero() {
			recoveryAt = now.Add(c.d.recoveryCheckInterval())
		}
		if c.healthAt.IsZero() || recoveryAt.Before(c.healthAt) {
			c.healthAt = recoveryAt
		}
	}
	if status.CheckEnabled && status.Healthy && c.healthAt.IsZero() {
		c.healthAt = now.Add(max(c.d.CheckInterval, time.Millisecond))
	}
	needsCapacity := status.Session.Accepting && status.Session.RecoveryRequired &&
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
		if recoveryTimeout > 0 {
			c.startRecoveryCheck(recoveryTimeout)
		} else {
			c.start(c.requestedCheckKind())
		}
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
	case !status.Healthy && !c.healthAt.IsZero() && (capacityAt.IsZero() || !capacityAt.Before(c.healthAt)):
		c.d.setRecovery(RecoveryBackoff, c.healthAt, "")
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
