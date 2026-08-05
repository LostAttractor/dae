/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stats keeps process-lifetime availability statistics of nodes and
// outbound groups. The registries survive control-plane reloads so that
// uptime information is not reset by `dae reload`.
package stats

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

var ProcessStart = time.Now()

// Availability is a point-in-time view of the uptime of a node, or of a
// group on one network type.
type Availability struct {
	Seen           bool          // false until the first record
	Alive          bool          // current state
	AliveSince     time.Time     // start of the current up-streak; zero while down
	LastFailAt     time.Time     // last recorded check failure; zero if none
	LastCheckAt    time.Time     // last connectivity check; zero if none (groups, unchecked nodes)
	LastConnFailAt time.Time     // last connection failure reported by the data plane; zero if none
	UpRatio        float64       // up time / total time since first seen
	UpDuration     time.Duration // length of the current up-streak
}

type availability struct {
	mu             sync.Mutex
	firstSeen      time.Time // zero until the first record
	alive          bool
	aliveSince     time.Time
	lastFailAt     time.Time
	lastCheckAt    time.Time
	lastConnFailAt time.Time
	totalUp        time.Duration
	lastAcc        time.Time // last time totalUp was brought up to date
}

func (a *availability) record(alive, checked bool, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if checked {
		a.lastCheckAt = now
	}
	if a.firstSeen.IsZero() {
		a.firstSeen, a.lastAcc = now, now
		a.alive = alive
		if alive {
			a.aliveSince = now
		} else {
			a.lastFailAt = now
		}
		return
	}
	if a.alive {
		a.totalUp += now.Sub(a.lastAcc)
	}
	a.lastAcc = now
	if !alive {
		a.lastFailAt = now
	}
	if alive == a.alive {
		return
	}
	a.alive = alive
	if alive {
		a.aliveSince = now
	}
}

func (a *availability) snapshot(now time.Time) Availability {
	a.mu.Lock()
	defer a.mu.Unlock()
	snap := Availability{
		Seen:           !a.firstSeen.IsZero(),
		Alive:          a.alive,
		LastFailAt:     a.lastFailAt,
		LastCheckAt:    a.lastCheckAt,
		LastConnFailAt: a.lastConnFailAt,
	}
	if !snap.Seen {
		return snap
	}
	totalUp := a.totalUp
	if a.alive {
		snap.AliveSince = a.aliveSince
		snap.UpDuration = now.Sub(a.aliveSince)
		totalUp += now.Sub(a.lastAcc)
	}
	if total := now.Sub(a.firstSeen); total > 0 {
		snap.UpRatio = float64(totalUp) / float64(total)
	}
	return snap
}

// Node keys are node identities (see dialer.StatsKey) that stay stable across
// control-plane reloads.
var nodes sync.Map // key -> *availability

func nodeAvailability(key string) *availability {
	v, _ := nodes.LoadOrStore(key, &availability{})
	return v.(*availability)
}

// RecordNode records the state of a node. checked should be true when the
// state comes from a connectivity check (as opposed to registration).
func RecordNode(key, subtag, name string, alive, checked bool) {
	nodeAvailability(key).record(alive, checked, time.Now())

	labels := prometheus.Labels{"subtag": subtag, "dialer": name}
	if alive {
		common.NodeAlive.With(labels).Set(1)
	} else {
		common.NodeAlive.With(labels).Set(0)
		common.NodeLastFailure.With(labels).SetToCurrentTime()
	}
}

// RecordNodeConnFail records that traffic through the node failed outside of
// scheduled connectivity checks.
func RecordNodeConnFail(key string) {
	a := nodeAvailability(key)
	a.mu.Lock()
	a.lastConnFailAt = time.Now()
	a.mu.Unlock()
}

func GetNode(key string) Availability {
	v, ok := nodes.Load(key)
	if !ok {
		return Availability{}
	}
	return v.(*availability).snapshot(time.Now())
}

var groups sync.Map // group name -> *[4]availability

func RecordGroup(name string, networkIndex int, alive bool) {
	v, _ := groups.LoadOrStore(name, &[4]availability{})
	v.(*[4]availability)[networkIndex].record(alive, false, time.Now())

	value := 0.0
	if alive {
		value = 1
	}
	common.GroupAlive.With(prometheus.Labels{
		"outbound": name,
		"network":  common.IndexToNetworkType(networkIndex).String(),
	}).Set(value)
}

func GetGroup(name string, networkIndex int) Availability {
	v, ok := groups.Load(name)
	if !ok {
		return Availability{}
	}
	return v.(*[4]availability)[networkIndex].snapshot(time.Now())
}
