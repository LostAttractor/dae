// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common/stats"
)

// Share creates another group-local member of the same configured path.
// A retired runtime cannot be resurrected, even while retained callers drain.
func (d *Dialer) Share(property *Property, statsScope string) (*Dialer, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return nil, false
	}
	member := &Dialer{
		pathRuntime:  d.pathRuntime,
		Property:     property,
		statsKey:     makeStatsKey(property, statsScope),
		checkEnabled: true,
	}
	member.statsID = stats.NodeID(member.statsKey)
	d.members[member] = struct{}{}
	return member, true
}

func (d *pathRuntime) membersSnapshot() []*Dialer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	members := make([]*Dialer, 0, len(d.members))
	for member := range d.members {
		if member.active {
			members = append(members, member)
		}
	}
	return members
}

func (d *pathRuntime) notifyGroups(force SelectionForceMask) {
	type notification struct {
		member *Dialer
		group  DialerGroup
	}
	d.mu.RLock()
	notifications := make([]notification, 0, len(d.members))
	for member := range d.members {
		if member.active && member.group != nil && member.group.observer != nil {
			notifications = append(notifications, notification{member, member.group.observer})
		}
	}
	d.mu.RUnlock()
	// Group callbacks may select paths and change demand. Never hold mu here.
	for _, notification := range notifications {
		notification.group.DialerChanged(notification.member, force)
	}
}

func (d *pathRuntime) recordLatencyLocked(latency time.Duration, success bool) {
	if !success {
		return
	}
	d.measuredAt = time.Now()
	d.lastLatency = latency
	for member := range d.members {
		if member.active && member.group != nil {
			member.group.recordLatency(latency)
		}
	}
}

// Any selected/tracked member keeps the shared worker enabled. Explicit checks
// and recovery for retained callers retain their separate one-shot demand.
func (d *pathRuntime) updateCheckDemandLocked() {
	enabled := false
	for member := range d.members {
		enabled = enabled || member.active && member.checkEnabled
	}
	if d.checkPaused == !enabled {
		return
	}
	d.checkPaused = !enabled
	if enabled {
		d.pendingCheck |= checkRequestEnvironment
	} else {
		d.pendingCheck &^= checkRequestEnvironment
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
		if !d.measuredAt.IsZero() && d.group != nil {
			d.group.recordLatency(d.lastLatency)
		}
		if d.initialCheckCompletedLocked() || !d.checkedAt.IsZero() {
			d.recordMemberAvailability(d.healthyLocked(d.sessionSnapshot()), false, time.Time{})
		}
		d.updateCheckDemandLocked()
	}
	d.mu.Unlock()
	d.pathRuntime.activateCheck(start)
	d.signalConnectivityCheck()
}
