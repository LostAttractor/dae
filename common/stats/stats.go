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
	*availabilityStore

	startedAt time.Time

	pathsMu        sync.RWMutex
	paths          map[Path]*pathCounters
	directFallback atomic.Int64
	samplePathsMu  sync.Mutex
	samplePaths    map[*pathCounters]struct{}
	samplePeak     int

	devicesMu sync.RWMutex
	devices   map[[6]byte]*Store

	externalReadErrors atomic.Uint64

	samplerMu        sync.Mutex
	samplerRunning   bool
	samplingMu       sync.RWMutex
	windowStartedAt  time.Time
	history          [api.TrafficHistorySampleCount]map[Path]trafficRate
	completedSamples uint64

	lastReload atomic.Int64
	metrics    storeMetrics
}

// DefaultStore records process-wide statistics without starting background work.
// The daemon owns its traffic sampler through StartSampling.
var DefaultStore = newStoreAt(time.Now())

func newStoreAt(windowStartedAt time.Time) *Store {
	return &Store{
		availabilityStore: newAvailabilityStore(),
		startedAt:         windowStartedAt,
		paths:             make(map[Path]*pathCounters),
		samplePaths:       make(map[*pathCounters]struct{}),
		windowStartedAt:   windowStartedAt,
		metrics:           newStoreMetrics(),
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
