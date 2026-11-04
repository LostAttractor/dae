/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"math"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/outbound/internal/checktime"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

const (
	checkBackoffInitialInterval = time.Second
	supportRetryInitialInterval = time.Second
	// Unknown capabilities back off faster than retries of a known healthy path.
	supportRetryMultiplier = 4
	// A failed path waits a quarter of its downtime so far between attempts.
	// Recovery is noticed within 25% of the outage, while a dead path needs
	// only logarithmically many probes to reach check_interval_max.
	recoveryRetryDivisor = 4
)

// recoveryRetryDelay spaces the attempts of a path that failed, whatever
// operation the next attempt is, so every caller shares one cadence.
func (c *connectivityChecker) recoveryRetryDelay(now time.Time) time.Duration {
	c.d.mu.RLock()
	defer c.d.mu.RUnlock()
	return c.recoveryRetryDelayLocked(now)
}

func (c *connectivityChecker) recoveryRetryDelayLocked(now time.Time) time.Duration {
	var downtime time.Duration
	if since := c.d.failures.downSince; !since.IsZero() {
		downtime = now.Sub(since)
	}
	maximum := c.d.CheckIntervalMax
	return checktime.Jitter(min(max(downtime/recoveryRetryDivisor, checkBackoffInitialInterval), maximum), maximum)
}

func (c *connectivityChecker) scheduleSupport() {
	if !c.supportPending() {
		c.supportAt = time.Time{}
		return
	}
	if c.supportAt.IsZero() {
		now := time.Now()
		if c.d.awaitingRecovery() {
			// A failed path that never confirmed a mode recovers by discovering one.
			c.supportAt = now.Add(c.recoveryRetryDelay(now))
			return
		}
		c.supportAt = now.Add(checktime.Jitter(c.retryInterval, c.d.CheckIntervalMax))
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
	if reasons&(checkRequestEnvironment|checkRequestManual|checkRequestDataPlane|checkRequestVerification) != 0 {
		c.resetHealthRetry()
	}
}

func (c *connectivityChecker) resetHealthRetry() {
	c.healthInterval = c.d.CheckInterval
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
		} else if c.d.initialCheckCompleted() && !c.supportPending() && !firstSupportedNetwork(c.d.networkStates()).Valid() {
			c.blockedBy = "no_supported_network"
			c.stopRetries()
			return
		}
	}
	c.scheduleSupport()
}

func (c *connectivityChecker) updateInitialSchedule(success bool) {
	if !c.d.initialCheckCompleted() {
		c.healthAt = time.Now().Add(checktime.Jitter(c.retryInterval, c.d.CheckIntervalMax))
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
	if c.staggerNext {
		delay = checktime.Jitter(c.healthInterval, math.MaxInt64)
		c.staggerNext = false
	}
	c.healthAt = time.Now().Add(delay)
}

func (c *connectivityChecker) updateHealthSchedule(success bool) {
	now := time.Now()
	if !success {
		c.healthAt = now.Add(c.recoveryRetryDelay(now))
		return
	}
	c.healthInterval = c.d.CheckInterval
	delay := c.healthInterval
	if c.staggerNext {
		delay = checktime.Jitter(delay, math.MaxInt64)
		c.staggerNext = false
	}
	c.healthAt = now.Add(delay)
}

// dispatch is the only scheduler entry point. Event handlers update facts and
// deadlines; here we choose one operation or arm the single wake-up timer.
func (c *connectivityChecker) dispatch() {
	c.timer.Stop()
	if c.cancel != nil || c.d.ctx.Err() != nil {
		return
	}
	// Further selection checks join running ones; a requested check waits
	// for them and runs before any further one.
	if c.selecting() {
		if !c.d.connectivityCheckRequested() {
			c.startSelectionChecks()
		}
		return
	}
	status := c.d.runtimeStatus()
	if c.d.session != nil && status.Session.State == netproxy.SessionClosed {
		c.stopRetries()
		c.d.setRecovery(api.RecoveryStopped, time.Time{}, "")
		return
	}
	if c.d.connectivityCheckRequested() {
		c.start(c.requestedCheckKind())
		return
	}
	if c.startSelectionChecks() {
		return
	}
	if c.blockedBy != "" {
		c.d.setRecovery(api.RecoveryBlocked, time.Time{}, c.blockedBy)
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
			c.d.setRecovery(api.RecoveryReady, time.Time{}, "")
			return
		}
		// Selected failover paths and retained callers still need capacity.
		// Recover it while demand exists, then stop checking once healthy.
		if status.Healthy {
			c.healthAt = time.Time{}
		} else if c.healthAt.IsZero() {
			// A failed discovery still has a retry deadline. Retained callers
			// need recovery, but must not turn that backoff into a busy loop.
			c.healthAt = c.supportAt
			if c.healthAt.IsZero() {
				c.healthAt = time.Now()
			}
		}
		c.supportAt = time.Time{}
	}
	if c.libraryRequested && status.Session.RecoveryExecutor == netproxy.RecoveryLibraryManaged && !status.Session.Accepting {
		c.d.setRecovery(api.RecoveryConnecting, time.Time{}, "protocol_recovery")
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
	// Monitoring resumes the schedule of a path that failed while unmonitored.
	if status.CheckEnabled && c.healthAt.IsZero() && c.supportAt.IsZero() && c.d.awaitingRecovery() {
		c.healthAt = now.Add(c.recoveryRetryDelay(now))
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
		c.d.setRecovery(api.RecoveryBackoff, c.healthAt, "")
	case needsCapacity && c.capacityBlockReason != "":
		c.d.updateRecovery(api.RecoveryBlocked, time.Time{}, c.capacityBlockReason, "replenish")
	case needsCapacity && !capacityAt.IsZero():
		c.d.updateRecovery(api.RecoveryBackoff, capacityAt, "capacity", "replenish")
	case !status.Healthy && !next.IsZero():
		c.d.setRecovery(api.RecoveryBackoff, next, "")
	case recoveryTimeout > 0 && !c.healthAt.IsZero():
		c.d.setRecovery(api.RecoveryBackoff, c.healthAt, "")
	default:
		c.d.setRecovery(api.RecoveryReady, time.Time{}, "")
	}
}

func nextRetryInterval(interval, maximum time.Duration) time.Duration {
	if interval >= maximum/time.Duration(supportRetryMultiplier) {
		return maximum
	}
	return min(interval*time.Duration(supportRetryMultiplier), maximum)
}

func initialRetryInterval(maximum time.Duration) time.Duration {
	return min(supportRetryInitialInterval, maximum)
}

func (c *connectivityChecker) supportPending() bool {
	c.d.mu.RLock()
	defer c.d.mu.RUnlock()
	if !c.d.initialCheckCompletedLocked() {
		return false
	}
	return len(c.d.discoveryModesLocked()) != 0
}
