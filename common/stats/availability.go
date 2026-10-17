/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
)

// availabilityStore owns node and group histories, recovery counters and the
// current selection sources. Traffic sampling never acquires its lock.
type availabilityStore struct {
	mu         sync.Mutex
	nodes      map[string]*nodeStats
	groups     map[string]*groupStats
	selections []SelectionMetricsSource
	metrics    availabilityMetrics
}

func newAvailabilityStore() *availabilityStore {
	return &availabilityStore{
		nodes:   make(map[string]*nodeStats),
		groups:  make(map[string]*groupStats),
		metrics: newAvailabilityMetrics(),
	}
}

// Reconcile removes availability state that does not belong to the newly
// committed control plane. Retained identities preserve their process-lifetime
// history; identities removed and later re-added start fresh.
func (s *availabilityStore) Reconcile(activeNodes map[string]NodeIdentity, activeGroups map[string]struct{}, sources ...SelectionMetricsSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nodes := make(map[string]*nodeStats, len(activeNodes))
	for key, identity := range activeNodes {
		state := s.nodes[key]
		if state == nil || state.NodeIdentity != identity {
			state = &nodeStats{NodeIdentity: identity}
		}
		nodes[key] = state
	}
	s.nodes = nodes

	groups := make(map[string]*groupStats, len(activeGroups))
	for name := range activeGroups {
		group := s.groups[name]
		if group == nil {
			group = new(groupStats)
		}
		groups[name] = group
	}
	s.groups = groups
	s.selections = slices.Clone(sources)
}

// NodeIdentity describes an availability identity retained by the currently
// committed control plane.
type NodeIdentity struct {
	Subtag string
	Name   string
}

type availability struct {
	firstSeen                time.Time
	totalUp                  time.Duration
	lastAcc                  time.Time
	failureStartedAt         time.Time
	completedFailureDuration time.Duration
	alive                    bool
	aliveSince               time.Time
	lastCheck                time.Time
	lastConnFail             time.Time
	checksTotal              int64
	checksFailed             int64
	checksSinceAlive         int64
	recent                   recentAvailability
}

type nodeStats struct {
	NodeIdentity
	availability
}

func (a *availability) record(alive, checked bool, now, failureStartedAt time.Time) {
	previouslyAlive := a.alive
	firstObservation := a.firstSeen.IsZero()
	transitionAt := now
	if !alive && !failureStartedAt.IsZero() {
		transitionAt = failureStartedAt
	}
	if transitionAt.After(now) {
		transitionAt = now
	}
	if !a.lastAcc.IsZero() && transitionAt.Before(a.lastAcc) {
		transitionAt = a.lastAcc
	}
	if firstObservation {
		a.firstSeen = transitionAt
	} else if previouslyAlive {
		a.totalUp += transitionAt.Sub(a.lastAcc)
	}
	a.lastAcc = now
	if alive != previouslyAlive {
		if alive {
			a.aliveSince = now
			if !a.failureStartedAt.IsZero() {
				a.completedFailureDuration = max(now.Sub(a.failureStartedAt), 0)
			}
		}
		a.alive = alive
	}
	if !alive && (firstObservation || previouslyAlive) {
		a.failureStartedAt = transitionAt
		a.completedFailureDuration = 0
	}
	if checked {
		a.lastCheck = now
		a.checksTotal++
		if !alive {
			a.checksFailed++
		} else if alive != previouslyAlive {
			a.checksSinceAlive = 1
		} else {
			a.checksSinceAlive++
		}
	}
	a.recent.record(now, transitionAt, alive, checked)
}

func (a *availability) snapshot(now time.Time) api.Availability {
	if a.firstSeen.IsZero() {
		return api.Availability{}
	}
	snapshot := api.Availability{
		Seen:                 true,
		Alive:                a.alive,
		LastFailureStartedAt: a.failureStartedAt,
		LastCheckAt:          a.lastCheck,
		LastConnFailAt:       a.lastConnFail,
		ChecksTotal:          a.checksTotal,
		ChecksFailed:         a.checksFailed,
		ChecksSinceAlive:     a.checksSinceAlive,
		Recent24h:            a.recent.snapshot(a.firstSeen, now),
	}
	totalUp := a.totalUp
	if snapshot.Alive {
		snapshot.AliveSince = a.aliveSince
		totalUp += now.Sub(a.lastAcc)
	}
	if !snapshot.LastFailureStartedAt.IsZero() {
		snapshot.LastFailureDuration = a.completedFailureDuration
		if !snapshot.Alive {
			snapshot.LastFailureDuration = max(now.Sub(a.failureStartedAt), 0)
		}
	}
	if total := now.Sub(a.firstSeen); total > 0 {
		snapshot.UpRatio = float64(totalUp) / float64(total)
	}
	return snapshot
}

// NodeID is the value of the "id" label of node-level series. A 128-bit
// prefix keeps labels compact while making accidental collisions negligible.
func NodeID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func (s *availabilityStore) recordNode(key string, alive, checked bool, failureStartedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.nodes[key]; state != nil {
		if state.alive && !alive {
			s.metrics.nodeUnavailable.WithLabelValues(NodeID(key), state.Subtag, state.Name).Inc()
		}
		state.record(alive, checked, time.Now(), failureStartedAt)
	}
}

func (s *availabilityStore) RecordNodeCheck(key string, alive bool, failureStartedAt time.Time) {
	s.recordNode(key, alive, true, failureStartedAt)
}

func (s *availabilityStore) RecordNodeState(key string, alive bool, failureStartedAt time.Time) {
	s.recordNode(key, alive, false, failureStartedAt)
}

// RecordNodeConnFail records a data-plane connection failure. It is a no-op
// for nodes that have never been recorded.
func (s *availabilityStore) RecordNodeConnFail(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.nodes[key]
	if state == nil {
		return
	}
	state.lastConnFail = time.Now()
}

func (s *availabilityStore) GetNode(key string) api.Availability {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.nodes[key]
	if state == nil {
		return api.Availability{}
	}
	return state.snapshot(time.Now())
}

type groupStats struct {
	availability
	states recentGroupStates
}

func (s *availabilityStore) RecordGroup(name string, available bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group := s.groups[name]
	if group == nil {
		return
	}
	now := time.Now()
	group.record(available, false, now, time.Time{})
	group.states.record(now, available)
}

func (s *availabilityStore) GetGroup(name string) api.GroupAvailability {
	s.mu.Lock()
	defer s.mu.Unlock()
	group := s.groups[name]
	if group == nil {
		return api.GroupAvailability{Recent: emptyGroupStateWindow()}
	}
	now := time.Now()
	recent := group.states.snapshot(now)
	return api.GroupAvailability{
		Availability: group.snapshot(now),
		Recent:       recent,
	}
}
