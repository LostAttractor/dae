/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common"
)

type DialerGroup interface {
	DialerChanged(d *Dialer, forceSelection SelectionForceMask)
}

// SelectionForceMask identifies networks whose selector refresh ignores tolerance.
type SelectionForceMask uint8

const (
	SelectionForceNone SelectionForceMask = 0
)

// SelectionForceFor returns a mask containing one valid network.
func SelectionForceFor(index common.NetworkIndex) SelectionForceMask {
	if !index.Valid() {
		return SelectionForceNone
	}
	return 1 << index
}

// Contains reports whether tolerance should be ignored for a network.
func (m SelectionForceMask) Contains(index common.NetworkIndex) bool {
	return m&SelectionForceFor(index) != 0
}

// groupBinding owns policy and successful latency samples for one group member.
// All fields are protected by the shared pathRuntime.mu.
type groupBinding struct {
	observer        DialerGroup
	latency         latencyWindow
	failureRecovery time.Duration
	probeTimeout    time.Duration
	recovered       bool
}

func (d *Dialer) RegisterDialerGroup(group DialerGroup, emaAlpha float64, failureRecovery, probeTimeout time.Duration) {
	d.mu.Lock()
	if emaAlpha == 0 {
		emaAlpha = DefaultEmaAlpha
	}
	if failureRecovery == 0 {
		failureRecovery = DefaultFailureRecovery
	}
	if probeTimeout == 0 {
		probeTimeout = DefaultProbeTimeout
	}
	d.group = &groupBinding{
		observer:        group,
		latency:         latencyWindow{alpha: emaAlpha},
		failureRecovery: failureRecovery,
		probeTimeout:    probeTimeout,
	}
	d.mu.Unlock()
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
