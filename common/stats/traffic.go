/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"errors"
	"maps"
	"math"
	"math/bits"
	"slices"
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
	path         Path
	sampling     atomic.Bool
	active       atomic.Int64
	total        atomic.Int64
	upload       atomic.Uint64
	download     atomic.Uint64
	rateInvalid  atomic.Bool
	lastSample   api.TrafficCounters
	lastActivity uint64
}

// Connection accounts for one logical TCP, smux, or UDP connection. Payload
// records update exact cumulative totals immediately; the sampler is
// responsible only for rates. Connection owners publish external counter samples.
type Connection struct {
	store  *Store
	stats  *pathCounters
	totals *pathCounters
	device *Connection

	stateMu              sync.Mutex
	closed               bool
	lastExternalCounters api.TrafficCounters
	externalInvalid      bool
}

// admitPath runs admit while retirement is excluded, so a path cannot retire
// between lookup and admission. Existing paths need only the read lock; live
// payload updates stay atomic.
func (s *Store) admitPath(path Path, admit func(*pathCounters)) {
	s.pathsMu.RLock()
	if counters := s.paths[path]; counters != nil {
		admit(counters)
		s.pathsMu.RUnlock()
		return
	}
	s.pathsMu.RUnlock()
	s.pathsMu.Lock()
	defer s.pathsMu.Unlock()
	counters := s.paths[path]
	if counters == nil {
		counters = &pathCounters{path: path}
		s.paths[path] = counters
		s.pathPeak = max(s.pathPeak, len(s.paths))
	}
	admit(counters)
}

func (s *Store) OpenConnection(path Path, directFallback bool) *Connection {
	var counters *pathCounters
	s.admitPath(path, func(admitted *pathCounters) {
		admitted.total.Add(1)
		admitted.active.Add(1)
		counters = admitted
	})
	var totals *pathCounters
	if path.Network.Valid() {
		totals = &s.networks[path.Network]
		totals.total.Add(1)
		totals.active.Add(1)
	}
	if directFallback {
		s.directFallback.Add(1)
	}
	s.track(counters)
	return &Connection{store: s, stats: counters, totals: totals}
}

// DirectFallbackConnections counts no-connectivity fallbacks to direct
// established in userspace across all paths; the kernel forwards other fallback
// flows without accounting. Like traffic totals, it survives control-plane reloads.
func (s *Store) DirectFallbackConnections() int64 {
	return s.directFallback.Load()
}

func (c *Connection) RecordUpload(bytes uint64) {
	if bytes == 0 {
		return
	}
	c.stats.upload.Add(bytes)
	if c.totals != nil {
		c.totals.upload.Add(bytes)
	}
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
	if c.totals != nil {
		c.totals.download.Add(bytes)
	}
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
		counters.lastActivity = s.completedSamples + 1
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
			previous := historySample[counters.path]
			previous.UploadBytesPerSecond = addRate(previous.UploadBytesPerSecond, rate.UploadBytesPerSecond)
			previous.DownloadBytesPerSecond = addRate(previous.DownloadBytesPerSecond, rate.DownloadBytesPerSecond)
			historySample[counters.path] = previous
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
	slot := s.completedSamples % api.TrafficHistorySampleCount
	s.history[slot] = historySample
	clear(s.networkHistory[slot][:])
	for path, rate := range historySample {
		if path.Network.Valid() {
			network := &s.networkHistory[slot][path.Network]
			network.UploadBytesPerSecond = addRate(network.UploadBytesPerSecond, rate.UploadBytesPerSecond)
			network.DownloadBytesPerSecond = addRate(network.DownloadBytesPerSecond, rate.DownloadBytesPerSecond)
		}
	}
	s.completedSamples++
	s.retirePaths()
	// Sample devices without excluding admission to known devices; only the
	// removal of idle devices excludes it.
	s.devicesMu.RLock()
	devices := slices.Collect(maps.Values(s.devices))
	s.devicesMu.RUnlock()
	for _, device := range devices {
		device.sampleAt(now)
	}
	s.devicesMu.Lock()
	defer s.devicesMu.Unlock()
	for mac, device := range s.devices {
		device.pathsMu.RLock()
		idle := len(device.paths) == 0
		device.pathsMu.RUnlock()
		if idle {
			delete(s.devices, mac)
		}
	}
	if s.devicePeak > 4*max(len(s.devices), 32) {
		devices := make(map[[6]byte]*Store, len(s.devices))
		maps.Copy(devices, s.devices)
		s.devices, s.devicePeak = devices, len(devices)
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
	if c.totals != nil {
		c.totals.active.Add(-1)
	}
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

type TrafficSnapshot struct {
	Paths                     map[Path]api.PathStats
	Networks                  [common.NetworkTypeCount]api.PathStats
	RetiredGroups             map[string][common.NetworkTypeCount]api.PathStats
	Groups                    map[string]struct{} // Configured groups; device stores leave it nil to count all.
	StartedAt                 time.Time
	DirectFallbackConnections int64
}

func (s *Store) snapshot(includeHistory bool) TrafficSnapshot {
	s.samplingMu.RLock()
	snapshot := TrafficSnapshot{Paths: make(map[Path]api.PathStats), StartedAt: s.startedAt, DirectFallbackConnections: s.DirectFallbackConnections()}
	for network := range s.networks {
		snapshot.Networks[network] = s.networks[network].snapshot()
		if includeHistory {
			count := int(min(s.completedSamples, api.TrafficHistorySampleCount))
			history := api.TrafficHistory{UploadBytesPerSecond: make([]uint64, count), DownloadBytesPerSecond: make([]uint64, count)}
			start := (s.completedSamples - uint64(count)) % api.TrafficHistorySampleCount
			for i := range count {
				rate := s.networkHistory[(start+uint64(i))%api.TrafficHistorySampleCount][network]
				history.UploadBytesPerSecond[i], history.DownloadBytesPerSecond[i] = rate.UploadBytesPerSecond, rate.DownloadBytesPerSecond
			}
			snapshot.Networks[network].History = history
		}
	}
	s.pathsMu.RLock()
	snapshot.RetiredGroups = maps.Clone(s.retiredGroups)
	// Reconcile replaces the set instead of mutating it.
	snapshot.Groups = s.currentGroups
	for path, counters := range s.paths {
		pathStats := counters.snapshot()
		if includeHistory {
			pathStats.History = s.pathHistoryLocked(path)
		}
		snapshot.Paths[path] = pathStats
	}
	s.pathsMu.RUnlock()
	s.samplingMu.RUnlock()
	return snapshot
}

// GroupTotals sums retained and retired paths by outbound and network. Totals
// cover the process lifetime of a group name, so neither node churn nor
// removing and re-adding the group decreases them; a removed group is hidden
// until configured again. Status and Prometheus share it.
func (s TrafficSnapshot) GroupTotals() map[string][common.NetworkTypeCount]api.PathStats {
	groups := make(map[string][common.NetworkTypeCount]api.PathStats, len(s.RetiredGroups))
	for name, networks := range s.RetiredGroups {
		if s.configured(name) {
			groups[name] = networks
		}
	}
	for path, values := range s.Paths {
		if !path.InGroup() || !s.configured(path.Outbound) {
			continue
		}
		networks := groups[path.Outbound]
		AddPathStats(&networks[path.Network], values)
		groups[path.Outbound] = networks
	}
	return groups
}

func (s TrafficSnapshot) configured(group string) bool {
	_, configured := s.Groups[group]
	return configured || s.Groups == nil
}

// InGroup reports whether the path carries a group's traffic through a node.
func (p Path) InGroup() bool {
	return p.Network.Valid() && p.Outbound != "" && p.NodeID != ""
}

// AddPathStats accumulates counters and aligned history samples, saturating rates.
func AddPathStats(dst *api.PathStats, other api.PathStats) {
	dst.ActiveConnections += other.ActiveConnections
	dst.TotalConnections += other.TotalConnections
	dst.UploadBytes += other.UploadBytes
	dst.DownloadBytes += other.DownloadBytes
	dst.History.UploadBytesPerSecond = addHistorySamples(dst.History.UploadBytesPerSecond, other.History.UploadBytesPerSecond)
	dst.History.DownloadBytesPerSecond = addHistorySamples(dst.History.DownloadBytesPerSecond, other.History.DownloadBytesPerSecond)
}

func addHistorySamples(current, other []uint64) []uint64 {
	if len(current) == 0 {
		return append([]uint64(nil), other...)
	}
	for i, value := range other {
		current[i] = addRate(current[i], value)
	}
	return current
}

// Snapshot returns retained path detail without sampling connections.
func (s *Store) Snapshot() map[Path]api.PathStats {
	return s.snapshot(false).Paths
}

// SnapshotWithHistory adds the latest completed five-second samples.
func (s *Store) SnapshotWithHistory() map[Path]api.PathStats {
	return s.snapshot(true).Paths
}

// TrafficSnapshot includes bounded process-lifetime network totals, independent
// of retained path detail. All status and metric consumers use this projection.
func (s *Store) TrafficSnapshot() TrafficSnapshot { return s.snapshot(true) }

func (c *pathCounters) snapshot() api.PathStats {
	// Read active before total, opposite to admission, to preserve active <= total.
	active := c.active.Load()
	return api.PathStats{ActiveConnections: active, TotalConnections: c.total.Load(), UploadBytes: c.upload.Load(), DownloadBytes: c.download.Load()}
}

// Reconcile retains detail for current identities while old connections drain.
// groups lists every configured group, true when it checks connectivity: all
// keep traffic totals, while only checking groups track availability.
func (s *Store) Reconcile(nodes map[string]NodeIdentity, groups map[string]bool, sources ...SelectionMetricsSource) {
	configured := make(map[string]struct{}, len(groups))
	checked := make(map[string]struct{}, len(groups))
	for name, checks := range groups {
		configured[name] = struct{}{}
		if checks {
			checked[name] = struct{}{}
		}
	}
	s.availabilityStore.Reconcile(nodes, checked, sources...)
	current := make(map[string]NodeIdentity, len(nodes))
	for key, identity := range nodes {
		current[NodeID(key)] = identity
	}
	s.pathsMu.Lock()
	s.currentNodes, s.currentGroups = current, configured
	s.pathsMu.Unlock()
}

func (s *Store) retirePaths() {
	s.pathsMu.Lock()
	defer s.pathsMu.Unlock()
	for path, counters := range s.paths {
		identity, current := s.currentNodes[path.NodeID]
		_, group := s.currentGroups[path.Outbound]
		if current && group && identity.Name == path.Dialer && identity.Subtag == path.Subtag {
			continue
		}
		if counters.active.Load() != 0 || counters.sampling.Load() || s.completedSamples-counters.lastActivity < api.TrafficHistorySampleCount {
			continue
		}
		delete(s.paths, path)
		// Kept per group name, including removed groups, which may return.
		if path.InGroup() {
			if s.retiredGroups == nil {
				s.retiredGroups = make(map[string][common.NetworkTypeCount]api.PathStats)
			}
			networks := s.retiredGroups[path.Outbound]
			totals := counters.snapshot()
			networks[path.Network].TotalConnections += totals.TotalConnections
			networks[path.Network].UploadBytes += totals.UploadBytes
			networks[path.Network].DownloadBytes += totals.DownloadBytes
			s.retiredGroups[path.Outbound] = networks
		}
		labels := pathLabelValues(path)
		s.metrics.dialDuration.DeleteLabelValues(labels...)
		s.metrics.errors.DeleteLabelValues(labels...)
	}
	if s.pathPeak > 4*max(len(s.paths), 32) {
		paths := make(map[Path]*pathCounters, len(s.paths))
		maps.Copy(paths, s.paths)
		s.paths = paths
		s.pathPeak = len(s.paths)
	}
}

func addRate(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return sum
}
