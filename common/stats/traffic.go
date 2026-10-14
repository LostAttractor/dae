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
	path        Path
	sampling    atomic.Bool
	active      atomic.Int64
	total       atomic.Int64
	upload      atomic.Uint64
	download    atomic.Uint64
	rateInvalid atomic.Bool
	lastSample  api.TrafficCounters
}

// Connection accounts for one logical TCP, smux, or UDP connection. Payload
// records update exact process-lifetime path totals immediately; the sampler is
// responsible only for rates. Connection owners publish external counter samples.
type Connection struct {
	store  *Store
	stats  *pathCounters
	device *Connection

	stateMu              sync.Mutex
	closed               bool
	lastExternalCounters api.TrafficCounters
	externalInvalid      bool
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
		counters = &pathCounters{path: path}
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
	s.track(counters)
	return &Connection{store: s, stats: counters}
}

// DirectFallbackConnections counts established no-connectivity fallbacks to
// direct across all paths. Like traffic totals, it survives control-plane reloads.
func (s *Store) DirectFallbackConnections() int64 {
	return s.directFallback.Load()
}

func (c *Connection) RecordUpload(bytes uint64) {
	if bytes == 0 {
		return
	}
	c.stats.upload.Add(bytes)
	c.store.track(c.stats)
	if c.device != nil {
		c.device.RecordUpload(bytes)
	}
}

func (c *Connection) RecordDownload(bytes uint64) {
	if bytes == 0 {
		return
	}
	c.stats.download.Add(bytes)
	c.store.track(c.stats)
	if c.device != nil {
		c.device.RecordDownload(bytes)
	}
}

func (c *Connection) invalidateRate() {
	c.stats.rateInvalid.Store(true)
	c.store.track(c.stats)
	if c.device != nil {
		c.device.invalidateRate()
	}
}

// A sampled path stays enrolled while it has live connections. Packet updates
// then touch only atomics; a late update re-enrolls an idle path once.
func (s *Store) track(counters *pathCounters) {
	if counters.sampling.Load() || !counters.sampling.CompareAndSwap(false, true) {
		return
	}
	s.samplePathsMu.Lock()
	s.samplePaths[counters] = struct{}{}
	s.samplePeak = max(s.samplePeak, len(s.samplePaths))
	s.samplePathsMu.Unlock()
}

// UpdateCounters publishes cumulative externally observed payload totals. The
// owner settles its final sample before Close. Queries never invoke an external
// source or affect connection lifetime. Do not also record these bytes as deltas.
func (c *Connection) UpdateCounters(counters api.TrafficCounters, sampleErr error) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return errors.New("connection is closed")
	}
	if sampleErr == nil && (counters.UploadBytes < c.lastExternalCounters.UploadBytes ||
		counters.DownloadBytes < c.lastExternalCounters.DownloadBytes) {
		sampleErr = errors.New("external counters moved backwards")
	}
	if sampleErr != nil {
		c.store.externalReadErrors.Add(1)
		c.externalInvalid = true
		c.invalidateRate()
		return sampleErr
	}
	if c.externalInvalid {
		c.invalidateRate()
		c.externalInvalid = false
	}
	c.RecordUpload(counters.UploadBytes - c.lastExternalCounters.UploadBytes)
	c.RecordDownload(counters.DownloadBytes - c.lastExternalCounters.DownloadBytes)
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

func (s *Store) sampleAt(now time.Time) {
	s.samplingMu.Lock()
	defer s.samplingMu.Unlock()
	elapsed := now.Sub(s.windowStartedAt)
	if elapsed <= 0 {
		return
	}
	s.windowStartedAt = now

	var historySample map[Path]trafficRate
	s.samplePathsMu.Lock()
	for counters := range s.samplePaths {
		current := api.TrafficCounters{
			UploadBytes:   counters.upload.Load(),
			DownloadBytes: counters.download.Load(),
		}
		var rate trafficRate
		if !counters.rateInvalid.Swap(false) {
			rate = trafficRate{
				UploadBytesPerSecond:   bytesPerSecond(current.UploadBytes-counters.lastSample.UploadBytes, elapsed),
				DownloadBytesPerSecond: bytesPerSecond(current.DownloadBytes-counters.lastSample.DownloadBytes, elapsed),
			}
		}
		if rate != (trafficRate{}) {
			if historySample == nil {
				historySample = make(map[Path]trafficRate)
			}
			historySample[counters.path] = rate
		}
		counters.lastSample = current
		if counters.active.Load() == 0 {
			counters.sampling.Store(false)
			// A writer may have observed sampling=true just before retirement.
			// Either this recheck retains its increment, or the writer observes
			// false and queues the path after we release samplePathsMu.
			if counters.active.Load() != 0 || counters.upload.Load() != current.UploadBytes || counters.download.Load() != current.DownloadBytes || counters.rateInvalid.Load() {
				counters.sampling.Store(true)
			} else {
				delete(s.samplePaths, counters)
			}
		}
	}
	// Go maps retain their table after deletion. Compact after a large batch
	// retires so future iterations scale with current work, not a past peak.
	if s.samplePeak > 4*max(len(s.samplePaths), 32) {
		active := make(map[*pathCounters]struct{}, len(s.samplePaths))
		for counters := range s.samplePaths {
			active[counters] = struct{}{}
		}
		s.samplePaths, s.samplePeak = active, len(active)
	}
	s.samplePathsMu.Unlock()
	s.history[s.completedSamples%api.TrafficHistorySampleCount] = historySample
	s.completedSamples++
	s.devicesMu.RLock()
	defer s.devicesMu.RUnlock()
	for _, device := range s.devices {
		device.sampleAt(now)
	}
}

func (c *Connection) Close() error {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil
	}
	c.closed = true
	c.stateMu.Unlock()
	c.stats.active.Add(-1)
	c.store.track(c.stats)
	if c.device != nil {
		return c.device.Close()
	}
	return nil
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

// Snapshot returns the latest published totals without sampling connections.
func (s *Store) Snapshot() map[Path]api.PathStats {
	return s.snapshot(false)
}

// SnapshotWithHistory adds the latest completed five-second samples.
func (s *Store) SnapshotWithHistory() map[Path]api.PathStats {
	return s.snapshot(true)
}
