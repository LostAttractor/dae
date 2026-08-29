/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
)

const trafficRateWindow = time.Second

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

type TrafficRate struct {
	UploadBytesPerSecond   uint64 `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond uint64 `json:"download_bytes_per_second"`
}

// PathStats is the process-lifetime state of one outbound path plus its latest
// traffic-rate sample.
type PathStats struct {
	ActiveConnections int64 `json:"active_connections"`
	TotalConnections  int64 `json:"total_connections"`
	TrafficCounters
	TrafficRate
}

func (s *PathStats) UnmarshalJSON(data []byte) error {
	var fields struct {
		ActiveConnections      *int64  `json:"active_connections"`
		TotalConnections       *int64  `json:"total_connections"`
		UploadBytes            *uint64 `json:"upload_bytes"`
		DownloadBytes          *uint64 `json:"download_bytes"`
		UploadBytesPerSecond   *uint64 `json:"upload_bytes_per_second"`
		DownloadBytesPerSecond *uint64 `json:"download_bytes_per_second"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fields); err != nil {
		return err
	}
	switch {
	case fields.ActiveConnections == nil:
		return errors.New("path stats is missing active_connections")
	case fields.TotalConnections == nil:
		return errors.New("path stats is missing total_connections")
	case fields.UploadBytes == nil:
		return errors.New("path stats is missing upload_bytes")
	case fields.DownloadBytes == nil:
		return errors.New("path stats is missing download_bytes")
	case fields.UploadBytesPerSecond == nil:
		return errors.New("path stats is missing upload_bytes_per_second")
	case fields.DownloadBytesPerSecond == nil:
		return errors.New("path stats is missing download_bytes_per_second")
	}
	*s = PathStats{
		ActiveConnections: *fields.ActiveConnections,
		TotalConnections:  *fields.TotalConnections,
		TrafficCounters: TrafficCounters{
			UploadBytes:   *fields.UploadBytes,
			DownloadBytes: *fields.DownloadBytes,
		},
		TrafficRate: TrafficRate{
			UploadBytesPerSecond:   *fields.UploadBytesPerSecond,
			DownloadBytesPerSecond: *fields.DownloadBytesPerSecond,
		},
	}
	return nil
}

func (s *PathStats) Add(other PathStats) {
	s.ActiveConnections += other.ActiveConnections
	s.TotalConnections += other.TotalConnections
	s.UploadBytes += other.UploadBytes
	s.DownloadBytes += other.DownloadBytes
	s.UploadBytesPerSecond += other.UploadBytesPerSecond
	s.DownloadBytesPerSecond += other.DownloadBytesPerSecond
}

type pathCounters struct {
	active   atomic.Int64
	total    atomic.Int64
	upload   atomic.Uint64
	download atomic.Uint64
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
}

// Store owns process-lifetime runtime statistics. Its zero value is not usable.
type Store struct {
	startedAt time.Time

	pathsMu sync.RWMutex
	paths   map[Path]*pathCounters

	externalMu          sync.RWMutex
	externalConnections map[*Connection]struct{}
	externalReadErrors  atomic.Uint64

	samplingMu      sync.RWMutex
	windowStartedAt time.Time
	lastSample      map[Path]TrafficCounters
	rates           map[Path]TrafficRate

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
		lastSample:          make(map[Path]TrafficCounters),
		rates:               make(map[Path]TrafficRate),
		nodes:               make(map[string]*nodeStats),
		groups:              make(map[string]*groupStats),
		metrics:             newStoreMetrics(),
	}
}

func (s *Store) run() {
	ticker := time.NewTicker(trafficRateWindow)
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

func (s *Store) OpenConnection(path Path) *Connection {
	counters := s.pathCounters(path)
	counters.total.Add(1)
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
		return err
	}
	if counters.UploadBytes < c.lastExternalCounters.UploadBytes ||
		counters.DownloadBytes < c.lastExternalCounters.DownloadBytes {
		return errors.New("external counters moved backwards")
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

func calculateRate(current, previous TrafficCounters, elapsed time.Duration) TrafficRate {
	return TrafficRate{
		UploadBytesPerSecond:   bytesPerSecond(current.UploadBytes-previous.UploadBytes, elapsed),
		DownloadBytesPerSecond: bytesPerSecond(current.DownloadBytes-previous.DownloadBytes, elapsed),
	}
}

func (s *Store) refreshExternalCounters() error {
	s.externalMu.RLock()
	connections := make([]*Connection, 0, len(s.externalConnections))
	for connection := range s.externalConnections {
		connections = append(connections, connection)
	}
	s.externalMu.RUnlock()

	var err error
	for _, connection := range connections {
		connection.stateMu.Lock()
		refreshErr := connection.refreshExternalCountersLocked()
		connection.stateMu.Unlock()
		if refreshErr != nil {
			s.externalReadErrors.Add(1)
			err = errors.Join(err, refreshErr)
		}
	}
	return err
}

func (s *Store) sampleAt(now time.Time) {
	s.samplingMu.Lock()
	defer s.samplingMu.Unlock()
	elapsed := now.Sub(s.windowStartedAt)
	if elapsed <= 0 {
		return
	}
	s.windowStartedAt = now

	_ = s.refreshExternalCounters()

	rates := make(map[Path]TrafficRate)
	s.pathsMu.RLock()
	for path, counters := range s.paths {
		current := TrafficCounters{
			UploadBytes:   counters.upload.Load(),
			DownloadBytes: counters.download.Load(),
		}
		rates[path] = calculateRate(current, s.lastSample[path], elapsed)
		s.lastSample[path] = current
	}
	s.pathsMu.RUnlock()
	s.rates = rates
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

// Snapshot refreshes active external sources, then returns exact path totals
// and the latest sampled rates.
func (s *Store) Snapshot() (map[Path]PathStats, error) {
	if err := s.refreshExternalCounters(); err != nil {
		return nil, err
	}

	snapshot := make(map[Path]PathStats)
	// Match sampleAt's lock order while pairing totals with one sampled rate set.
	s.samplingMu.RLock()
	s.pathsMu.RLock()
	for path, counters := range s.paths {
		snapshot[path] = PathStats{
			ActiveConnections: counters.active.Load(),
			TotalConnections:  counters.total.Load(),
			TrafficCounters: TrafficCounters{
				UploadBytes:   counters.upload.Load(),
				DownloadBytes: counters.download.Load(),
			},
			TrafficRate: s.rates[path],
		}
	}
	s.pathsMu.RUnlock()
	s.samplingMu.RUnlock()
	return snapshot, nil
}
