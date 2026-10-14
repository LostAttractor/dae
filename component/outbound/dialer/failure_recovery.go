// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common"
)

func (d *pathRuntime) resetRecoveryObservationLocked() {
	d.failures.recoverySince, d.failures.recoveryVerifiedAt = time.Time{}, time.Time{}
	for i := range d.health.modes {
		f := &d.health.modes[i].failures
		f.recoverySince, f.recoveryVerifiedAt = time.Time{}, time.Time{}
	}
}

// Only completed checks advance recovery; mode observations never restore
// another mode's priority. Completed group windows survive sleep.
func (d *pathRuntime) recordRecoverySuccessLocked() {
	d.recordRecoveryObservationLocked(&d.failures, common.NetworkInvalid)
}

func (d *pathRuntime) recordModeRecoverySuccessLocked(network common.NetworkIndex) {
	d.recordRecoveryObservationLocked(&d.health.modes[network].failures, network)
}

func (d *pathRuntime) recordRecoveryObservationLocked(f *pathFailures, network common.NetworkIndex) {
	if !f.failedBefore {
		return
	}
	now := time.Now()
	if f.recoverySince.IsZero() {
		f.recoverySince = now
	}
	f.recoveryVerifiedAt = now
	for member := range d.members {
		if group := member.group; group != nil && now.Sub(f.recoverySince) >= group.failureRecovery {
			if network.Valid() {
				group.modeRecovered[network] = true
			} else {
				group.recovered = true
			}
		}
	}
}

func (d *pathRuntime) recoveryCheckInterval() time.Duration {
	return min(5*time.Second, d.CheckInterval)
}

func (d *pathRuntime) recoveryCheckPlan() (at time.Time, timeout time.Duration) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.checksConnectivity || !d.healthyLocked(d.sessionSnapshot()) {
		return
	}
	inspect := func(f *pathFailures, network common.NetworkIndex) {
		if !f.failedBefore {
			return
		}
		for member := range d.members {
			group := member.group
			if !member.active || !member.checkEnabled || group == nil {
				continue
			}
			recovered := group.recovered
			if network.Valid() {
				recovered = group.modeRecovered[network]
			}
			if recovered {
				continue
			}
			if timeout == 0 || group.probeTimeout < timeout {
				timeout = group.probeTimeout
			}
			if !f.recoverySince.IsZero() {
				deadline := f.recoverySince.Add(group.failureRecovery)
				if at.IsZero() || deadline.Before(at) {
					at = deadline
				}
			}
			if !f.recoveryVerifiedAt.IsZero() {
				next := f.recoveryVerifiedAt.Add(d.recoveryCheckInterval())
				if at.IsZero() || next.Before(at) {
					at = next
				}
			}
		}
	}
	inspect(&d.failures, common.NetworkInvalid)
	for i := range d.health.modes {
		if d.health.modes[i].phase == healthHealthy {
			inspect(&d.health.modes[i].failures, common.NetworkIndex(i))
		}
	}
	return
}

// Recovery shares one bounded selection operation; choose the oldest unfinished
// mode so a fast mode cannot starve a sibling's recovery observation.
func (c *connectivityChecker) startRecoveryCheck(timeout time.Duration) {
	c.d.mu.Lock()
	network := firstSupportedNetwork(c.d.health.networks)
	var oldest time.Time
	selected := false
	for i := range c.d.health.modes {
		mode := &c.d.health.modes[i]
		if mode.phase != healthHealthy || !mode.failures.failedBefore {
			continue
		}
		needed := false
		for member := range c.d.members {
			needed = needed || member.active && member.checkEnabled && member.group != nil && !member.group.modeRecovered[i]
		}
		if needed && (!selected || mode.failures.recoveryVerifiedAt.Before(oldest)) {
			network, oldest, selected = common.NetworkIndex(i), mode.failures.recoveryVerifiedAt, true
		}
	}
	c.d.queueSelectionCheckLocked(network, time.Now().Add(timeout)).waiters++
	c.d.mu.Unlock()
	c.startSelectionCheck()
}

func (d *Dialer) recoveryDegradationLocked(f *pathFailures, recovered bool) (bool, time.Duration, time.Duration) {
	required := DefaultFailureRecovery
	if d.group != nil {
		required = d.group.failureRecovery
	}
	if recovered {
		return false, required, required
	}
	return f.failedBefore, max(0, min(f.recoveryVerifiedAt.Sub(f.recoverySince), required)), required
}

func (d *Dialer) modeDegradationLocked(network common.NetworkIndex) (bool, time.Duration, time.Duration) {
	recovered, modeRecovered := false, false
	if d.group != nil {
		recovered, modeRecovered = d.group.recovered, d.group.modeRecovered[network]
	}
	degraded, elapsed, required := d.recoveryDegradationLocked(&d.failures, recovered)
	modeDegraded, modeElapsed, _ := d.recoveryDegradationLocked(&d.health.modes[network].failures, modeRecovered)
	if modeDegraded && (!degraded || modeElapsed < elapsed) {
		elapsed = modeElapsed
	}
	return degraded || modeDegraded, elapsed, required
}

func (d *Dialer) degradationLocked() (degraded bool, elapsed time.Duration, required time.Duration) {
	for i := range d.health.modes {
		if d.health.networks[i] == networkUnsupported {
			continue
		}
		bad, progress, window := d.modeDegradationLocked(common.NetworkIndex(i))
		required = window
		if bad && (!degraded || progress < elapsed) {
			elapsed = progress
		}
		degraded = degraded || bad
	}
	if !degraded {
		elapsed = required
	}
	return
}

func (d *pathRuntime) confirmModeFailureLocked(network common.NetworkIndex) {
	f := &d.health.modes[network].failures
	f.failedBefore = true
	f.recoverySince, f.recoveryVerifiedAt = time.Time{}, time.Time{}
	f.generation++
	for member := range d.members {
		if member.group != nil {
			member.group.modeRecovered[network] = false
		}
	}
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
