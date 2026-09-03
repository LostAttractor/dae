/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
)

const (
	TrafficHistoryInterval    = 5 * time.Second
	TrafficHistorySampleCount = 12
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

// TrafficCounters contains cumulative payload bytes for both directions.
type TrafficCounters struct {
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
}

type trafficRate struct {
	UploadBytesPerSecond   uint64
	DownloadBytesPerSecond uint64
}

type TrafficHistory struct {
	UploadBytesPerSecond   []uint64 `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond []uint64 `json:"download_bytes_per_second"`
}

func (h TrafficHistory) MarshalJSON() ([]byte, error) {
	if h.UploadBytesPerSecond == nil {
		h.UploadBytesPerSecond = []uint64{}
	}
	if h.DownloadBytesPerSecond == nil {
		h.DownloadBytesPerSecond = []uint64{}
	}
	type plain TrafficHistory
	return jsonv2.Marshal(plain(h))
}

func (h *TrafficHistory) UnmarshalJSON(data []byte) error {
	var fields struct {
		UploadBytesPerSecond   *[]uint64 `json:"upload_bytes_per_second"`
		DownloadBytesPerSecond *[]uint64 `json:"download_bytes_per_second"`
	}
	if err := jsonv2.Unmarshal(data, &fields, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if fields.UploadBytesPerSecond == nil {
		return errors.New("traffic history is missing upload_bytes_per_second")
	}
	if fields.DownloadBytesPerSecond == nil {
		return errors.New("traffic history is missing download_bytes_per_second")
	}
	if len(*fields.UploadBytesPerSecond) != len(*fields.DownloadBytesPerSecond) {
		return errors.New("traffic history directions have different sample counts")
	}
	if len(*fields.UploadBytesPerSecond) > TrafficHistorySampleCount {
		return fmt.Errorf("traffic history has %d samples, want at most %d", len(*fields.UploadBytesPerSecond), TrafficHistorySampleCount)
	}
	h.UploadBytesPerSecond = *fields.UploadBytesPerSecond
	h.DownloadBytesPerSecond = *fields.DownloadBytesPerSecond
	return nil
}

func addHistorySamples(current, other []uint64) []uint64 {
	if len(current) == 0 {
		return append([]uint64(nil), other...)
	}
	for i, value := range other {
		sum, carry := bits.Add64(current[i], value, 0)
		if carry != 0 {
			sum = math.MaxUint64
		}
		current[i] = sum
	}
	return current
}

func (h *TrafficHistory) add(other TrafficHistory) {
	h.UploadBytesPerSecond = addHistorySamples(h.UploadBytesPerSecond, other.UploadBytesPerSecond)
	h.DownloadBytesPerSecond = addHistorySamples(h.DownloadBytesPerSecond, other.DownloadBytesPerSecond)
}

// PathStats is the process-lifetime state and recent traffic history of one
// outbound path.
type PathStats struct {
	ActiveConnections   int64 `json:"active_connections"`
	TotalConnections    int64 `json:"total_connections"`
	FallbackConnections int64 `json:"fallback_connections"`
	TrafficCounters
	History TrafficHistory `json:"history"`
}

func (s *PathStats) UnmarshalJSON(data []byte) error {
	var fields struct {
		ActiveConnections   *int64          `json:"active_connections"`
		TotalConnections    *int64          `json:"total_connections"`
		FallbackConnections *int64          `json:"fallback_connections"`
		UploadBytes         *uint64         `json:"upload_bytes"`
		DownloadBytes       *uint64         `json:"download_bytes"`
		History             *TrafficHistory `json:"history"`
	}
	if err := jsonv2.Unmarshal(data, &fields, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	switch {
	case fields.ActiveConnections == nil:
		return errors.New("path stats is missing active_connections")
	case fields.TotalConnections == nil:
		return errors.New("path stats is missing total_connections")
	case fields.FallbackConnections == nil:
		return errors.New("path stats is missing fallback_connections")
	case fields.UploadBytes == nil:
		return errors.New("path stats is missing upload_bytes")
	case fields.DownloadBytes == nil:
		return errors.New("path stats is missing download_bytes")
	case fields.History == nil:
		return errors.New("path stats is missing history")
	}
	*s = PathStats{
		ActiveConnections:   *fields.ActiveConnections,
		TotalConnections:    *fields.TotalConnections,
		FallbackConnections: *fields.FallbackConnections,
		TrafficCounters: TrafficCounters{
			UploadBytes:   *fields.UploadBytes,
			DownloadBytes: *fields.DownloadBytes,
		},
		History: *fields.History,
	}
	return nil
}

func (s *PathStats) Add(other PathStats) {
	s.ActiveConnections += other.ActiveConnections
	s.TotalConnections += other.TotalConnections
	s.FallbackConnections += other.FallbackConnections
	s.UploadBytes += other.UploadBytes
	s.DownloadBytes += other.DownloadBytes
	s.History.add(other.History)
}

type pathCounters struct {
	active      atomic.Int64
	total       atomic.Int64
	fallback    atomic.Int64
	upload      atomic.Uint64
	download    atomic.Uint64
	rateInvalid atomic.Bool
	lastSample  TrafficCounters
}

// Connection accounts for one logical TCP, smux, or UDP connection. Payload
// records update exact process-lifetime path totals immediately; the sampler is
// responsible only for rates and external counter refreshes.
type Connection struct {
	store *Store
	stats *pathCounters

	stateMu              sync.Mutex
	closed               bool
	externalSource       func() (TrafficCounters, error)
	lastExternalCounters TrafficCounters
	externalInvalid      bool
}

// Store owns process-lifetime runtime statistics. Its zero value is not usable.
type Store struct {
	startedAt time.Time

	pathsMu sync.RWMutex
	paths   map[Path]*pathCounters

	externalMu          sync.RWMutex
	externalConnections map[*Connection]struct{}
	externalReadErrors  atomic.Uint64

	samplingMu       sync.RWMutex
	windowStartedAt  time.Time
	history          [TrafficHistorySampleCount]map[Path]trafficRate
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
	ticker := time.NewTicker(TrafficHistoryInterval)
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

func (s *Store) OpenConnection(path Path, fallback bool) *Connection {
	counters := s.pathCounters(path)
	counters.total.Add(1)
	if fallback {
		counters.fallback.Add(1)
	}
	counters.active.Add(1)
	return &Connection{store: s, stats: counters}
}

func (c *Connection) RecordUpload(bytes uint64) {
	c.stats.upload.Add(bytes)
}

func (c *Connection) RecordDownload(bytes uint64) {
	c.stats.download.Add(bytes)
}

func (c *Connection) AttachExternalCounters(source func() (TrafficCounters, error)) error {
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
		current := TrafficCounters{
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
	s.history[s.completedSamples%TrafficHistorySampleCount] = historySample
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

func (s *Store) pathHistoryLocked(path Path) TrafficHistory {
	count := int(min(s.completedSamples, TrafficHistorySampleCount))
	history := TrafficHistory{
		UploadBytesPerSecond:   make([]uint64, count),
		DownloadBytesPerSecond: make([]uint64, count),
	}
	start := int((s.completedSamples - uint64(count)) % TrafficHistorySampleCount)
	for i := 0; i < count; i++ {
		rate := s.history[(start+i)%TrafficHistorySampleCount][path]
		history.UploadBytesPerSecond[i] = rate.UploadBytesPerSecond
		history.DownloadBytesPerSecond[i] = rate.DownloadBytesPerSecond
	}
	return history
}

func (s *Store) snapshot(includeHistory bool) map[Path]PathStats {
	s.samplingMu.RLock()
	s.refreshExternalCounters()
	snapshot := make(map[Path]PathStats)
	s.pathsMu.RLock()
	for path, counters := range s.paths {
		// OpenConnection increments total, fallback, then active. Reading in the
		// opposite order preserves their invariants without affecting the hot path.
		active := counters.active.Load()
		fallback := counters.fallback.Load()
		total := counters.total.Load()
		pathStats := PathStats{
			ActiveConnections:   active,
			TotalConnections:    total,
			FallbackConnections: fallback,
			TrafficCounters: TrafficCounters{
				UploadBytes:   counters.upload.Load(),
				DownloadBytes: counters.download.Load(),
			},
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
func (s *Store) Snapshot() map[Path]PathStats {
	return s.snapshot(false)
}

// SnapshotWithHistory adds the latest completed five-second samples.
func (s *Store) SnapshotWithHistory() map[Path]PathStats {
	return s.snapshot(true)
}
