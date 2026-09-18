/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"errors"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
)

const (
	trafficDirectionUpload   = "upload"
	trafficDirectionDownload = "download"
)

// Path identifies the outbound path used by one logical connection.
type Path struct {
	NodeID   string
	Outbound string
	Subtag   string
	Dialer   string
	Network  common.NetworkIndex
}

type trafficRate struct {
	UploadBytesPerSecond   uint64
	DownloadBytesPerSecond uint64
}

type pathCounters struct {
	active      atomic.Int64
	total       atomic.Int64
	upload      atomic.Uint64
	download    atomic.Uint64
	rateInvalid atomic.Bool
	lastSample  api.TrafficCounters
}

// Connection accounts for one logical TCP, smux, or UDP connection. Payload
// records update exact process-lifetime path totals immediately; the sampler is
// responsible only for rates and external counter refreshes.
type Connection struct {
	store *Store
	stats *pathCounters

	stateMu              sync.Mutex
	closed               bool
	externalSource       func() (api.TrafficCounters, error)
	lastExternalCounters api.TrafficCounters
	externalInvalid      bool
}

// Store owns process-lifetime runtime statistics. Its zero value is not usable.
type Store struct {
	startedAt time.Time

	pathsMu        sync.RWMutex
	paths          map[Path]*pathCounters
	directFallback atomic.Int64

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

func (s *Store) pathCounters(path Path) *pathCounters {
	s.pathsMu.RLock()
	counters := s.paths[path]
	s.pathsMu.RUnlock()
	if counters != nil {
		return counters
	}

	s.pathsMu.Lock()
	defer s.pathsMu.Unlock()
	if counters = s.paths[path]; counters == nil {
		counters = new(pathCounters)
		s.paths[path] = counters
	}
	return counters
}

func (s *Store) OpenConnection(path Path, directFallback bool) *Connection {
	counters := s.pathCounters(path)
	counters.total.Add(1)
	if directFallback {
		s.directFallback.Add(1)
	}
	counters.active.Add(1)
	return &Connection{store: s, stats: counters}
}

// DirectFallbackConnections counts established no-connectivity fallbacks to
// direct across all paths. Like traffic totals, it survives control-plane reloads.
func (s *Store) DirectFallbackConnections() int64 {
	return s.directFallback.Load()
}

func (c *Connection) RecordUpload(bytes uint64) {
	c.stats.upload.Add(bytes)
}

func (c *Connection) RecordDownload(bytes uint64) {
	c.stats.download.Add(bytes)
}

func (c *Connection) AttachExternalCounters(source func() (api.TrafficCounters, error)) error {
	if source == nil {
		return errors.New("external counter source is nil")
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return errors.New("connection is closed")
	}
	if c.externalSource != nil {
		return errors.New("external counter source is already attached")
	}
	c.externalSource = source
	c.store.externalMu.Lock()
	c.store.externalConnections[c] = struct{}{}
	c.store.externalMu.Unlock()
	return nil
}

func (c *Connection) refreshExternalCountersLocked() error {
	if c.externalSource == nil {
		return nil
	}
	counters, err := c.externalSource()
	if err != nil {
		c.externalInvalid = true
		c.stats.rateInvalid.Store(true)
		return err
	}
	if counters.UploadBytes < c.lastExternalCounters.UploadBytes ||
		counters.DownloadBytes < c.lastExternalCounters.DownloadBytes {
		c.externalInvalid = true
		c.stats.rateInvalid.Store(true)
		return errors.New("external counters moved backwards")
	}
	if c.externalInvalid {
		c.stats.rateInvalid.Store(true)
		c.externalInvalid = false
	}
	c.stats.upload.Add(counters.UploadBytes - c.lastExternalCounters.UploadBytes)
	c.stats.download.Add(counters.DownloadBytes - c.lastExternalCounters.DownloadBytes)
	c.lastExternalCounters = counters
	return nil
}

func bytesPerSecond(bytes uint64, elapsed time.Duration) uint64 {
	if bytes == 0 || elapsed <= 0 {
		return 0
	}
	high, low := bits.Mul64(bytes, uint64(time.Second))
	divisor := uint64(elapsed)
	if high >= divisor {
		return math.MaxUint64
	}
	rate, _ := bits.Div64(high, low, divisor)
	return rate
}

func (s *Store) refreshExternalCounters() {
	s.externalMu.RLock()
	connections := make([]*Connection, 0, len(s.externalConnections))
	for connection := range s.externalConnections {
		connections = append(connections, connection)
	}
	s.externalMu.RUnlock()

	for _, connection := range connections {
		connection.stateMu.Lock()
		refreshErr := connection.refreshExternalCountersLocked()
		connection.stateMu.Unlock()
		if refreshErr != nil {
			s.externalReadErrors.Add(1)
		}
	}
}

func (s *Store) sampleAt(now time.Time) {
	s.samplingMu.Lock()
	defer s.samplingMu.Unlock()
	elapsed := now.Sub(s.windowStartedAt)
	if elapsed <= 0 {
		return
	}
	s.refreshExternalCounters()
	s.windowStartedAt = now

	var historySample map[Path]trafficRate
	s.pathsMu.RLock()
	for path, counters := range s.paths {
		current := api.TrafficCounters{
			UploadBytes:   counters.upload.Load(),
			DownloadBytes: counters.download.Load(),
		}
		if counters.rateInvalid.Swap(false) {
			counters.lastSample = current
			continue
		}
		rate := trafficRate{
			UploadBytesPerSecond:   bytesPerSecond(current.UploadBytes-counters.lastSample.UploadBytes, elapsed),
			DownloadBytesPerSecond: bytesPerSecond(current.DownloadBytes-counters.lastSample.DownloadBytes, elapsed),
		}
		if rate != (trafficRate{}) {
			if historySample == nil {
				historySample = make(map[Path]trafficRate)
			}
			historySample[path] = rate
		}
		counters.lastSample = current
	}
	s.pathsMu.RUnlock()
	s.history[s.completedSamples%api.TrafficHistorySampleCount] = historySample
	s.completedSamples++
}

func (c *Connection) Close() error {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil
	}
	c.closed = true
	var err error
	if c.externalSource != nil {
		err = c.refreshExternalCountersLocked()
		if err != nil {
			c.store.externalReadErrors.Add(1)
		}
		c.externalSource = nil
		c.store.externalMu.Lock()
		delete(c.store.externalConnections, c)
		c.store.externalMu.Unlock()
	}
	c.stateMu.Unlock()
	c.stats.active.Add(-1)
	return err
}

func (s *Store) pathHistoryLocked(path Path) api.TrafficHistory {
	count := int(min(s.completedSamples, api.TrafficHistorySampleCount))
	history := api.TrafficHistory{
		UploadBytesPerSecond:   make([]uint64, count),
		DownloadBytesPerSecond: make([]uint64, count),
	}
	start := int((s.completedSamples - uint64(count)) % api.TrafficHistorySampleCount)
	for i := range count {
		rate := s.history[(start+i)%api.TrafficHistorySampleCount][path]
		history.UploadBytesPerSecond[i] = rate.UploadBytesPerSecond
		history.DownloadBytesPerSecond[i] = rate.DownloadBytesPerSecond
	}
	return history
}

func (s *Store) snapshot(includeHistory bool) map[Path]api.PathStats {
	s.samplingMu.RLock()
	s.refreshExternalCounters()
	snapshot := make(map[Path]api.PathStats)
	s.pathsMu.RLock()
	for path, counters := range s.paths {
		// OpenConnection increments total before active. Reading in the
		// opposite order preserves their invariants without affecting the hot path.
		active := counters.active.Load()
		total := counters.total.Load()
		pathStats := api.PathStats{
			ActiveConnections: active,
			TotalConnections:  total,
			UploadBytes:       counters.upload.Load(),
			DownloadBytes:     counters.download.Load(),
		}
		if includeHistory {
			pathStats.History = s.pathHistoryLocked(path)
		}
		snapshot[path] = pathStats
	}
	s.pathsMu.RUnlock()
	s.samplingMu.RUnlock()
	return snapshot
}

// Snapshot refreshes active external sources and returns the latest known totals.
func (s *Store) Snapshot() map[Path]api.PathStats {
	return s.snapshot(false)
}

// SnapshotWithHistory adds the latest completed five-second samples.
func (s *Store) SnapshotWithHistory() map[Path]api.PathStats {
	return s.snapshot(true)
}
