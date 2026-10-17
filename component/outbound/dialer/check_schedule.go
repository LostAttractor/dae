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
)

func (c *connectivityChecker) scheduleSupport() {
	if !c.supportPending() {
		c.supportAt = time.Time{}
		return
	}
	if c.supportAt.IsZero() {
		deadline := time.Now().Add(checktime.Jitter(c.retryInterval, c.d.CheckIntervalMax))
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
	if applied.rediscover {
		c.scheduleRediscovery()
		return
	}
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

func (c *connectivityChecker) scheduleRediscovery() {
	c.rediscover = true
	c.retryInterval = initialRetryInterval(c.d.CheckIntervalMax)
	c.healthAt = time.Time{}
	c.supportAt = time.Now()
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
	c.backingOff = false
	if c.staggerNext {
		delay = checktime.Jitter(c.healthInterval, math.MaxInt64)
		c.staggerNext = false
	}
	c.healthAt = time.Now().Add(delay)
}

func (c *connectivityChecker) updateHealthSchedule(success bool) {
	maximum := c.d.CheckIntervalMax
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
		delay = checktime.Jitter(delay, maximum)
	} else if c.staggerNext {
		delay = checktime.Jitter(delay, math.MaxInt64)
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
		c.d.setRecovery(api.RecoveryStopped, time.Time{}, "")
		return
	}
	if c.d.connectivityCheckRequested() {
		c.start(c.requestedCheckKind())
		return
	}
	if c.startSelectionCheck() {
		return
	}
	if c.blockedBy != "" {
		c.d.setRecovery(api.RecoveryBlocked, time.Time{}, c.blockedBy)
		return
	}
	// Selection requests can finish discovery before the background sweep runs.
	if c.rediscover && !c.supportPending() {
		c.rediscover = false
	}
	if !status.CheckEnabled && !c.rediscover {
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
			// A failed rediscovery still has a retry deadline. Retained callers
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
