/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

func trafficTestPath(name string) Path {
	return Path{
		NodeID:   name,
		Outbound: name,
		Subtag:   "sub",
		Dialer:   "node",
		Network:  common.NetworkTCP4,
	}
}

func pathStats(t *testing.T, store *Store, path Path) api.PathStats {
	t.Helper()
	snapshot := store.Snapshot()
	stats, ok := snapshot[path]
	if !ok {
		t.Fatalf("path %v is absent from snapshot", path)
	}
	return stats
}

func pathStatsWithHistory(t *testing.T, store *Store, path Path) api.PathStats {
	t.Helper()
	snapshot := store.SnapshotWithHistory()
	stats, ok := snapshot[path]
	if !ok {
		t.Fatalf("path %v is absent from snapshot", path)
	}
	return stats
}

func TestStoreSamplesConnectionAndKeepsExactTotals(t *testing.T) {
	path := trafficTestPath(t.Name())
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	connection := store.OpenConnection(path, false)
	connection.RecordUpload(6000)
	connection.RecordDownload(17000)
	store.sampleAt(windowStart.Add(api.TrafficHistoryInterval))

	got := pathStats(t, store, path)
	want := api.PathStats{
		ActiveConnections: 1,
		TotalConnections:  1,
		UploadBytes:       6000,
		DownloadBytes:     17000,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path stats = %+v, want %+v", got, want)
	}
	history := pathStatsWithHistory(t, store, path).History
	if !reflect.DeepEqual(history, api.TrafficHistory{
		UploadBytesPerSecond:   []uint64{1200},
		DownloadBytesPerSecond: []uint64{3400},
	}) {
		t.Fatalf("traffic history = %+v", history)
	}

	store.sampleAt(windowStart.Add(2 * api.TrafficHistoryInterval))
	history = pathStatsWithHistory(t, store, path).History
	if !reflect.DeepEqual(history.UploadBytesPerSecond, []uint64{1200, 0}) ||
		!reflect.DeepEqual(history.DownloadBytesPerSecond, []uint64{3400, 0}) {
		t.Fatalf("idle traffic history = %+v", history)
	}
	connection.Close()
	got = pathStats(t, store, path)
	if got.ActiveConnections != 0 || got.TotalConnections != 1 {
		t.Fatalf("closed connection counts = %+v", got)
	}
}

func TestStoreHistoryKeepsLastMinute(t *testing.T) {
	path := trafficTestPath(t.Name())
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	connection := store.OpenConnection(path, false)
	defer connection.Close()

	for sample := 1; sample <= api.TrafficHistorySampleCount+2; sample++ {
		connection.RecordUpload(uint64(sample) * uint64(api.TrafficHistoryInterval/time.Second))
		store.sampleAt(windowStart.Add(time.Duration(sample) * api.TrafficHistoryInterval))
	}
	history := pathStatsWithHistory(t, store, path).History.UploadBytesPerSecond
	want := make([]uint64, api.TrafficHistorySampleCount)
	for i := range want {
		want[i] = uint64(i + 3)
	}
	if !reflect.DeepEqual(history, want) {
		t.Fatalf("upload history = %v, want %v", history, want)
	}
	if history := pathStats(t, store, path).History; history.UploadBytesPerSecond != nil || history.DownloadBytesPerSecond != nil {
		t.Fatalf("plain snapshot includes history: %+v", history)
	}
}

func TestStoreCountsFallbackConnections(t *testing.T) {
	path := trafficTestPath(t.Name())
	path.Outbound = "direct"
	store := newStoreAt(time.Now())
	regular := store.OpenConnection(path, false)
	fallback := store.OpenConnection(path, true)
	regular.Close()
	fallback.Close()

	got := pathStats(t, store, path)
	if got.TotalConnections != 2 || store.DirectFallbackConnections() != 1 {
		t.Fatalf("connection counts = %+v", got)
	}
	other := path
	other.Network = common.NetworkUDP6
	other.NodeID = "replacement-direct"
	store.OpenConnection(other, true).Close()
	store.RecordReload()
	if got := store.DirectFallbackConnections(); got != 2 {
		t.Fatalf("fallback total across paths and reload = %d, want 2", got)
	}
	if got := newStoreAt(time.Now()).DirectFallbackConnections(); got != 0 {
		t.Fatalf("new process inherited fallback total %d", got)
	}
}

func TestSnapshotKeepsConcurrentFallbackCountsConsistent(t *testing.T) {
	path := trafficTestPath(t.Name())
	store := newStoreAt(time.Now())
	store.pathCounters(path)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100000 {
			store.OpenConnection(path, true)
		}
	}()

	for {
		fallback := store.DirectFallbackConnections()
		got := pathStats(t, store, path)
		if fallback > got.TotalConnections || got.ActiveConnections > got.TotalConnections {
			t.Fatalf("inconsistent connection counts: %+v", got)
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func TestExternalRefreshFailureOnlySkipsAffectedPath(t *testing.T) {
	failedPath := trafficTestPath(t.Name() + "-failed")
	healthyPath := trafficTestPath(t.Name() + "-healthy")
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	failed := store.OpenConnection(failedPath, false)
	defer failed.Close()
	healthy := store.OpenConnection(healthyPath, false)
	defer healthy.Close()

	readFails := true
	if err := failed.AttachExternalCounters(func() (api.TrafficCounters, error) {
		if readFails {
			return api.TrafficCounters{}, errors.New("read failed")
		}
		return api.TrafficCounters{UploadBytes: 100}, nil
	}); err != nil {
		t.Fatal(err)
	}
	healthy.RecordUpload(5000)
	store.sampleAt(windowStart.Add(api.TrafficHistoryInterval))
	if store.completedSamples != 1 {
		t.Fatalf("history count after failed refresh = %d, want 1", store.completedSamples)
	}
	if got := pathStatsWithHistory(t, store, healthyPath).History.UploadBytesPerSecond; !reflect.DeepEqual(got, []uint64{1000}) {
		t.Fatalf("healthy path history = %v, want [1000]", got)
	}

	readFails = false
	healthy.RecordUpload(5000)
	store.sampleAt(windowStart.Add(2 * api.TrafficHistoryInterval))
	if got := pathStatsWithHistory(t, store, failedPath).History.UploadBytesPerSecond; !reflect.DeepEqual(got, []uint64{0, 0}) {
		t.Fatalf("failed path history = %v, want recovery window omitted", got)
	}
	if got := pathStatsWithHistory(t, store, healthyPath).History.UploadBytesPerSecond; !reflect.DeepEqual(got, []uint64{1000, 1000}) {
		t.Fatalf("healthy path history after recovery = %v", got)
	}
}

func TestConnectionCloseKeepsShortConnectionTotals(t *testing.T) {
	path := trafficTestPath(t.Name())
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	connection := store.OpenConnection(path, false)
	connection.RecordUpload(77)
	connection.RecordDownload(88)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	store.sampleAt(windowStart.Add(api.TrafficHistoryInterval))

	got := pathStats(t, store, path)
	if got.ActiveConnections != 0 || got.TotalConnections != 1 ||
		got.TrafficCounters != (api.TrafficCounters{UploadBytes: 77, DownloadBytes: 88}) {
		t.Fatalf("short connection stats = %+v", got)
	}
	history := pathStatsWithHistory(t, store, path).History
	if !reflect.DeepEqual(history.UploadBytesPerSecond, []uint64{15}) ||
		!reflect.DeepEqual(history.DownloadBytesPerSecond, []uint64{17}) {
		t.Fatalf("short connection history = %+v", history)
	}
}

func TestSnapshotRefreshesActiveExternalCounters(t *testing.T) {
	path := trafficTestPath(t.Name())
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(path, false)
	defer connection.Close()
	connection.RecordUpload(77)
	connection.RecordDownload(88)
	if err := connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		return api.TrafficCounters{UploadBytes: 23, DownloadBytes: 12}, nil
	}); err != nil {
		t.Fatal(err)
	}

	got := pathStats(t, store, path)
	if got.TrafficCounters != (api.TrafficCounters{UploadBytes: 100, DownloadBytes: 100}) {
		t.Fatalf("active connection totals = %+v", got.TrafficCounters)
	}
}

func TestConnectionRecordsAfterClose(t *testing.T) {
	path := trafficTestPath(t.Name())
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	connection := store.OpenConnection(path, false)
	connection.Close()
	connection.RecordUpload(77)
	store.sampleAt(windowStart.Add(api.TrafficHistoryInterval))

	got := pathStats(t, store, path)
	if got.UploadBytes != 77 {
		t.Fatalf("late upload stats = %+v", got)
	}
	if history := pathStatsWithHistory(t, store, path).History.UploadBytesPerSecond; !reflect.DeepEqual(history, []uint64{15}) {
		t.Fatalf("late upload history = %v", history)
	}
}

func TestConnectionRejectsInvalidExternalSources(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()), false)
	if err := connection.AttachExternalCounters(nil); err == nil {
		t.Fatal("nil external source was accepted")
	}
	if err := connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		return api.TrafficCounters{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		return api.TrafficCounters{}, nil
	}); err == nil {
		t.Fatal("second external source was accepted")
	}
	connection.Close()
	if err := connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		return api.TrafficCounters{}, nil
	}); err == nil {
		t.Fatal("closed connection accepted an external source")
	}
	if len(store.externalConnections) != 0 {
		t.Fatalf("closed connection remains registered: %d", len(store.externalConnections))
	}
}

func TestExternalCounterRollbackIsReported(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()), false)
	counters := api.TrafficCounters{UploadBytes: 10, DownloadBytes: 20}
	if err := connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		return counters, nil
	}); err != nil {
		t.Fatal(err)
	}
	store.Snapshot()
	counters.UploadBytes = 9
	if err := connection.Close(); err == nil {
		t.Fatal("external counter rollback was not reported")
	}
	if got := pathStats(t, store, trafficTestPath(t.Name())).TrafficCounters; got != (api.TrafficCounters{UploadBytes: 10, DownloadBytes: 20}) {
		t.Fatalf("rollback changed totals: %+v", got)
	}
}

func TestStoreKeepsTotalsAbovePrometheusPrecision(t *testing.T) {
	path := trafficTestPath(t.Name())
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	connection := store.OpenConnection(path, false)
	want := uint64(1<<53 + 1)
	connection.RecordUpload(want)
	connection.Close()
	store.sampleAt(windowStart.Add(api.TrafficHistoryInterval))

	got := pathStats(t, store, path)
	if got.UploadBytes != want {
		t.Fatalf("exact upload stats = %+v, want %d", got, want)
	}
}

func TestSnapshotSurvivesExternalReadFailure(t *testing.T) {
	store := newStoreAt(time.Now())
	path := trafficTestPath(t.Name())
	connection := store.OpenConnection(path, false)
	wantErr := errors.New("counter source failed")
	if err := connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		return api.TrafficCounters{}, wantErr
	}); err != nil {
		t.Fatal(err)
	}

	snapshot := store.Snapshot()
	if _, ok := snapshot[path]; !ok {
		t.Fatalf("failed external path is absent from snapshot: %+v", snapshot)
	}
	if got := store.externalReadErrors.Load(); got != 1 {
		t.Fatalf("external read errors = %d, want 1", got)
	}
	_ = connection.Close()
}

func TestConnectionCloseReportsFinalReadFailure(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()), false)
	wantErr := errors.New("counter source failed")
	if err := connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		return api.TrafficCounters{}, wantErr
	}); err != nil {
		t.Fatal(err)
	}

	if err := connection.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("close error = %v, want %v", err, wantErr)
	}
}

func TestStoreCollectsConnectionMetrics(t *testing.T) {
	path := trafficTestPath(t.Name())
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(path, true)
	connection.RecordUpload(42)
	connection.Close()
	store.OpenConnection(trafficTestPath(t.Name()+"-other"), false).Close()
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	uploadFound := false
	fallbackFound := false
	for _, family := range families {
		if family.GetName() == "dae_fallback_connections_total" {
			if len(family.Metric) != 1 || len(family.Metric[0].Label) != 0 {
				t.Fatalf("fallback metric retained per-path series: %v", family)
			}
		}
		for _, metric := range family.GetMetric() {
			if family.GetName() == "dae_fallback_connections_total" && metric.GetCounter().GetValue() == 1 {
				fallbackFound = true
			}
			if family.GetName() != "dae_traffic_bytes_total" {
				continue
			}
			direction := ""
			for _, label := range metric.GetLabel() {
				if label.GetName() == "direction" {
					direction = label.GetValue()
				}
			}
			if direction == trafficDirectionUpload && metric.GetCounter().GetValue() == 42 {
				uploadFound = true
			}
		}
	}
	if !uploadFound || !fallbackFound {
		t.Fatalf("connection metrics: upload=%v fallback=%v", uploadFound, fallbackFound)
	}
}

func TestConnectionRecordTrafficDoesNotAllocate(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()), false)
	defer connection.Close()

	allocs := testing.AllocsPerRun(1000, func() {
		connection.RecordUpload(1)
		connection.RecordDownload(1)
	})
	if allocs != 0 {
		t.Fatalf("steady-state traffic recording allocations = %v, want 0", allocs)
	}
}

func BenchmarkTrafficRecord(b *testing.B) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(b.Name()), false)
	defer connection.Close()
	b.ReportAllocs()
	for b.Loop() {
		connection.RecordUpload(1)
		connection.RecordDownload(1)
	}
}

func BenchmarkTrafficConnectionLifecycle(b *testing.B) {
	store := newStoreAt(time.Now())
	path := trafficTestPath(b.Name())
	connection := store.OpenConnection(path, false)
	_ = connection.Close()
	b.ReportAllocs()
	for b.Loop() {
		connection := store.OpenConnection(path, false)
		connection.RecordUpload(1)
		connection.RecordDownload(1)
		if err := connection.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkTrafficStore(pathCount int) (*Store, time.Time) {
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	for i := range pathCount {
		connection := store.OpenConnection(trafficTestPath(fmt.Sprintf("path-%d", i)), false)
		connection.RecordUpload(uint64(i + 1))
		connection.RecordDownload(uint64(i + 1))
		_ = connection.Close()
	}
	return store, windowStart
}

func BenchmarkTrafficSample(b *testing.B) {
	for _, pathCount := range []int{1, 64, 256} {
		b.Run(fmt.Sprintf("paths=%d", pathCount), func(b *testing.B) {
			store, now := benchmarkTrafficStore(pathCount)
			b.ReportAllocs()
			for b.Loop() {
				now = now.Add(api.TrafficHistoryInterval)
				store.sampleAt(now)
			}
		})
	}
}

var benchmarkTrafficSnapshot map[Path]api.PathStats

func BenchmarkTrafficSnapshot(b *testing.B) {
	for _, pathCount := range []int{1, 64, 256} {
		b.Run(fmt.Sprintf("paths=%d", pathCount), func(b *testing.B) {
			store, _ := benchmarkTrafficStore(pathCount)
			b.ReportAllocs()
			for b.Loop() {
				benchmarkTrafficSnapshot = store.Snapshot()
			}
		})
	}
}

func BenchmarkTrafficExternalCounters(b *testing.B) {
	for _, connectionCount := range []int{1, 64, 256} {
		b.Run(fmt.Sprintf("connections=%d", connectionCount), func(b *testing.B) {
			store := newStoreAt(time.Now())
			connections := make([]*Connection, 0, connectionCount)
			source := func() (api.TrafficCounters, error) {
				return api.TrafficCounters{UploadBytes: 1, DownloadBytes: 1}, nil
			}
			for i := range connectionCount {
				connection := store.OpenConnection(trafficTestPath(fmt.Sprintf("path-%d", i)), false)
				if err := connection.AttachExternalCounters(source); err != nil {
					b.Fatal(err)
				}
				connections = append(connections, connection)
			}
			b.Cleanup(func() {
				for _, connection := range connections {
					_ = connection.Close()
				}
			})
			b.ReportAllocs()
			for b.Loop() {
				store.refreshExternalCounters()
			}
		})
	}
}
