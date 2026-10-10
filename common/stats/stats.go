/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stats owns process-lifetime availability, connection and traffic
// state. Prometheus and status are read-only projections of this typed state.
package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/api"
)

// Store owns process-lifetime runtime statistics. Its zero value is not usable.
type Store struct {
	startedAt time.Time

	pathsMu        sync.RWMutex
	paths          map[Path]*pathCounters
	directFallback atomic.Int64

	devicesMu sync.RWMutex
	devices   map[[6]byte]*Store

	externalMu          sync.RWMutex
	externalConnections map[*Connection]struct{}
	externalReadErrors  atomic.Uint64

	samplingMu       sync.RWMutex
	windowStartedAt  time.Time
	history          [api.TrafficHistorySampleCount]map[Path]trafficRate
	completedSamples uint64

	availabilityMu sync.Mutex
	nodes          map[string]*nodeStats
	groups         map[string]*groupStats
	lastReload     atomic.Int64
	metrics        storeMetrics
}

var DefaultStore = newStoreAt(time.Now())

func init() { go DefaultStore.run() }

func newStoreAt(windowStartedAt time.Time) *Store {
	return &Store{
		startedAt:           windowStartedAt,
		paths:               make(map[Path]*pathCounters),
		externalConnections: make(map[*Connection]struct{}),
		windowStartedAt:     windowStartedAt,
		nodes:               make(map[string]*nodeStats),
		groups:              make(map[string]*groupStats),
		metrics:             newStoreMetrics(),
	}
}

func (s *Store) run() {
	ticker := time.NewTicker(api.TrafficHistoryInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.sampleAt(time.Now())
	}
}

func (s *Store) RecordReload() {
	s.lastReload.Store(time.Now().Unix())
}

func (s *Store) StartedAt() time.Time {
	return s.startedAt
}

// LastReload returns when the last control-plane reload finished, or the zero
// time if no reload has happened since process start.
func (s *Store) LastReload() time.Time {
	seconds := s.lastReload.Load()
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

// Reconcile removes availability state that does not belong to the newly
// committed control plane. Retained identities preserve their process-lifetime
// history; identities removed and later re-added start fresh.
func (s *Store) Reconcile(activeNodes map[string]NodeIdentity, activeGroups map[string]struct{}) {
	s.availabilityMu.Lock()
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
	s.availabilityMu.Unlock()
	s.metrics.resetCurrent()
}
