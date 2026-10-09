// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import "time"

func (d *pathRuntime) resetRecoveryObservationLocked() {
	d.failures.recoverySince, d.failures.recoveryVerifiedAt = time.Time{}, time.Time{}
}

// Only completed health checks advance the observation window. Merely reaching
// a deadline never restores priority. Completed group windows survive sleep.
func (d *pathRuntime) recordRecoverySuccessLocked() {
	if !d.failures.failedBefore {
		return
	}
	now := time.Now()
	if d.failures.recoverySince.IsZero() {
		d.failures.recoverySince = now
	}
	d.failures.recoveryVerifiedAt = now
	for member := range d.members {
		if group := member.group; group != nil && now.Sub(d.failures.recoverySince) >= group.failureRecovery {
			group.recovered = true
		}
	}
}

func (d *pathRuntime) recoveryCheckInterval() time.Duration {
	interval := 5 * time.Second
	if d.CheckInterval > 0 {
		interval = min(interval, d.CheckInterval)
	}
	return interval
}

// Share observation probes across groups, including groups with different
// recovery durations. The earliest unfinished deadline gets an endpoint check.
func (d *pathRuntime) recoveryCheckPlan() (at time.Time, timeout time.Duration) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.failures.failedBefore || d.health.phase != healthHealthy || !d.healthyLocked(d.sessionSnapshot()) {
		return
	}
	for member := range d.members {
		group := member.group
		if !member.active || !member.checkEnabled || group == nil || group.recovered {
			continue
		}
		if timeout == 0 || group.probeTimeout < timeout {
			timeout = group.probeTimeout
		}
		if !d.failures.recoverySince.IsZero() {
			deadline := d.failures.recoverySince.Add(group.failureRecovery)
			if at.IsZero() || deadline.Before(at) {
				at = deadline
			}
		}
	}
	if timeout > 0 && !d.failures.recoveryVerifiedAt.IsZero() {
		next := d.failures.recoveryVerifiedAt.Add(d.recoveryCheckInterval())
		if at.IsZero() || next.Before(at) {
			at = next
		}
	}
	return
}

// The connectivity worker owns this background waiter; selection requests can
// join it and consume the same verified result through Check.
func (c *connectivityChecker) startRecoveryCheck(timeout time.Duration) {
	c.d.mu.Lock()
	network := firstSupportedNetwork(c.d.health.networks)
	c.d.queueSelectionCheckLocked(network, time.Now().Add(timeout)).waiters++
	c.d.mu.Unlock()
	c.startSelectionCheck()
}

func (d *Dialer) degradationLocked() (bool, time.Duration, time.Duration) {
	required := DefaultFailureRecovery
	if d.group != nil {
		required = d.group.failureRecovery
		if d.group.recovered {
			return false, required, required
		}
	}
	return d.failures.failedBefore, min(d.failures.recoveryVerifiedAt.Sub(d.failures.recoverySince), required), required
}

func (d *pathRuntime) confirmFailureLocked() {
	d.failures.failedBefore = true
	d.resetRecoveryObservationLocked()
	for member := range d.members {
		if member.group != nil {
			member.group.recovered = false
		}
	}
	d.failures.generation++
}
