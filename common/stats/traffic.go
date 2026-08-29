/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

const TrafficRateWindow = time.Second

const (
	TrafficDirectionUpload   = "upload"
	TrafficDirectionDownload = "download"
)

// TrafficIdentity is the attribution attached to one logical connection.
type TrafficIdentity struct {
	NodeID   string
	Outbound string
	Subtag   string
	Dialer   string
	Network  string
}

// TrafficCounters contains cumulative payload bytes for both directions.
type TrafficCounters struct {
	UploadBytes   uint64
	DownloadBytes uint64
}

func (c *TrafficCounters) Add(other TrafficCounters) {
	c.UploadBytes += other.UploadBytes
	c.DownloadBytes += other.DownloadBytes
}

type TrafficRate struct {
	UploadBytesPerSecond   uint64
	DownloadBytesPerSecond uint64
}

func (r *TrafficRate) Add(other TrafficRate) {
	r.UploadBytesPerSecond += other.UploadBytesPerSecond
	r.DownloadBytesPerSecond += other.DownloadBytesPerSecond
}

// TrafficSnapshot is the latest sampled rate of one active connection.
type TrafficSnapshot struct {
	Identity TrafficIdentity
	Rate     TrafficRate
}

// TrafficCounterSource supplies cumulative bytes transferred outside
// userspace, such as bytes redirected by the direct TCP sockmap path.
type TrafficCounterSource func() (TrafficCounters, error)

type trafficMetrics struct {
	upload   prometheus.Counter
	download prometheus.Counter
}

// TrafficConnection accounts for one logical TCP, smux, or UDP connection.
// Active forwarding paths only touch the atomic counters. Sampling and normal
// Prometheus publication happen outside those paths; a record racing with Close
// performs one final synchronous flush so successful bytes are not lost.
type TrafficConnection struct {
	tracker  *TrafficTracker
	identity TrafficIdentity

	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64
	closed        atomic.Bool

	stateMu              sync.Mutex
	lastSample           TrafficCounters
	lastPublished        TrafficCounters
	externalSource       TrafficCounterSource
	lastExternalCounters TrafficCounters
	metrics              trafficMetrics
}

type sampledConnection struct {
	connection *TrafficConnection
	snapshot   TrafficSnapshot
}

// The sampled values are immutable after publication. Snapshot filters their
// connection pointers against live close state so closed connections disappear
// immediately rather than at the next sample.
type publishedTrafficSnapshot struct {
	connections []sampledConnection
}

type TrafficTracker struct {
	activeMu          sync.RWMutex
	activeConnections map[*TrafficConnection]struct{}

	samplingMu      sync.Mutex
	windowStartedAt time.Time
	latest          atomic.Pointer[publishedTrafficSnapshot]
}

var DefaultTrafficTracker = newTrafficTracker()

func init() {
	go DefaultTrafficTracker.run()
}

func newTrafficTracker() *TrafficTracker {
	return newTrafficTrackerAt(time.Now())
}

func newTrafficTrackerAt(windowStartedAt time.Time) *TrafficTracker {
	return &TrafficTracker{
		activeConnections: make(map[*TrafficConnection]struct{}),
		windowStartedAt:   windowStartedAt,
	}
}

func (t *TrafficTracker) run() {
	ticker := time.NewTicker(TrafficRateWindow)
	defer ticker.Stop()
	for range ticker.C {
		t.sampleAt(time.Now())
	}
}

func trafficMetric(identity TrafficIdentity, direction string) prometheus.Counter {
	return common.TrafficBytes.WithLabelValues(
		identity.NodeID,
		identity.Outbound,
		identity.Subtag,
		identity.Dialer,
		identity.Network,
		direction,
	)
}

func (t *TrafficTracker) Open(identity TrafficIdentity) *TrafficConnection {
	connection := &TrafficConnection{
		tracker:  t,
		identity: identity,
		metrics: trafficMetrics{
			upload:   trafficMetric(identity, TrafficDirectionUpload),
			download: trafficMetric(identity, TrafficDirectionDownload),
		},
	}
	t.activeMu.Lock()
	t.activeConnections[connection] = struct{}{}
	t.activeMu.Unlock()
	return connection
}

func (c *TrafficConnection) RecordUpload(bytes uint64) {
	c.uploadBytes.Add(bytes)
	c.flushLateRecord()
}

func (c *TrafficConnection) RecordDownload(bytes uint64) {
	c.downloadBytes.Add(bytes)
	c.flushLateRecord()
}

// A forwarding operation that raced with Close may report its successful
// write just after the final flush. Publish that late delta synchronously.
func (c *TrafficConnection) flushLateRecord() {
	if !c.closed.Load() {
		return
	}
	c.stateMu.Lock()
	c.publishMetricsLocked(c.totalsLocked())
	c.stateMu.Unlock()
}

func (c *TrafficConnection) AttachExternalCounters(source TrafficCounterSource) {
	c.stateMu.Lock()
	if !c.closed.Load() {
		c.externalSource = source
	}
	c.stateMu.Unlock()
}

func (c *TrafficConnection) readExternalCountersLocked() {
	if c.externalSource == nil {
		return
	}
	if counters, err := c.externalSource(); err == nil {
		c.lastExternalCounters = counters
	}
}

func (c *TrafficConnection) totalsLocked() TrafficCounters {
	c.readExternalCountersLocked()
	totals := TrafficCounters{
		UploadBytes:   c.uploadBytes.Load(),
		DownloadBytes: c.downloadBytes.Load(),
	}
	totals.Add(c.lastExternalCounters)
	return totals
}

// DetachExternalCounters folds the source's final cumulative values into the
// userspace counters before the underlying source is removed.
func (c *TrafficConnection) DetachExternalCounters() {
	c.stateMu.Lock()
	c.detachExternalCountersLocked()
	c.stateMu.Unlock()
}

func (c *TrafficConnection) detachExternalCountersLocked() {
	if c.externalSource == nil {
		return
	}
	c.readExternalCountersLocked()
	c.uploadBytes.Add(c.lastExternalCounters.UploadBytes)
	c.downloadBytes.Add(c.lastExternalCounters.DownloadBytes)
	c.externalSource = nil
	c.lastExternalCounters = TrafficCounters{}
}

func bytesPerSecond(bytes uint64, elapsed time.Duration) uint64 {
	if bytes == 0 || elapsed <= 0 {
		return 0
	}
	return uint64(float64(bytes) / elapsed.Seconds())
}

func calculateRate(current, previous TrafficCounters, elapsed time.Duration) TrafficRate {
	return TrafficRate{
		UploadBytesPerSecond:   bytesPerSecond(current.UploadBytes-previous.UploadBytes, elapsed),
		DownloadBytesPerSecond: bytesPerSecond(current.DownloadBytes-previous.DownloadBytes, elapsed),
	}
}

func (c *TrafficConnection) publishMetricsLocked(current TrafficCounters) {
	if current.UploadBytes > c.lastPublished.UploadBytes {
		c.metrics.upload.Add(float64(current.UploadBytes - c.lastPublished.UploadBytes))
	}
	if current.DownloadBytes > c.lastPublished.DownloadBytes {
		c.metrics.download.Add(float64(current.DownloadBytes - c.lastPublished.DownloadBytes))
	}
	c.lastPublished = current
}

func (c *TrafficConnection) sample(elapsed time.Duration) TrafficSnapshot {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	current := c.totalsLocked()
	c.publishMetricsLocked(current)
	snapshot := TrafficSnapshot{
		Identity: c.identity,
		Rate:     calculateRate(current, c.lastSample, elapsed),
	}
	c.lastSample = current
	return snapshot
}

func (t *TrafficTracker) activeSnapshot() []*TrafficConnection {
	t.activeMu.RLock()
	defer t.activeMu.RUnlock()

	connections := make([]*TrafficConnection, 0, len(t.activeConnections))
	for connection := range t.activeConnections {
		connections = append(connections, connection)
	}
	return connections
}

func (t *TrafficTracker) sampleAt(now time.Time) {
	t.samplingMu.Lock()
	defer t.samplingMu.Unlock()

	elapsed := now.Sub(t.windowStartedAt)
	if elapsed <= 0 {
		return
	}
	t.windowStartedAt = now

	active := t.activeSnapshot()
	published := &publishedTrafficSnapshot{
		connections: make([]sampledConnection, 0, len(active)),
	}
	for _, connection := range active {
		published.connections = append(published.connections, sampledConnection{
			connection: connection,
			snapshot:   connection.sample(elapsed),
		})
	}
	t.latest.Store(published)
}

func (t *TrafficTracker) remove(connection *TrafficConnection) {
	t.activeMu.Lock()
	delete(t.activeConnections, connection)
	t.activeMu.Unlock()
}

func (t *TrafficTracker) FlushCounters() {
	for _, connection := range t.activeSnapshot() {
		connection.stateMu.Lock()
		connection.publishMetricsLocked(connection.totalsLocked())
		connection.stateMu.Unlock()
	}
}

func (c *TrafficConnection) Close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	c.stateMu.Lock()
	c.detachExternalCountersLocked()
	c.publishMetricsLocked(c.totalsLocked())
	c.stateMu.Unlock()
	c.tracker.remove(c)
}

func (t *TrafficTracker) Snapshot() []TrafficSnapshot {
	published := t.latest.Load()
	if published == nil {
		return nil
	}

	active := make([]TrafficSnapshot, 0, len(published.connections))
	for _, sampled := range published.connections {
		if !sampled.connection.closed.Load() {
			active = append(active, sampled.snapshot)
		}
	}
	return active
}
