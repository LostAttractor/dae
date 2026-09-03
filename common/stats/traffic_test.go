/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

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

func pathStats(t *testing.T, store *Store, path Path) PathStats {
	t.Helper()
	snapshot := store.Snapshot()
	stats, ok := snapshot[path]
	if !ok {
		t.Fatalf("path %v is absent from snapshot", path)
	}
	return stats
}

func pathStatsWithHistory(t *testing.T, store *Store, path Path) PathStats {
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
	store.sampleAt(windowStart.Add(TrafficHistoryInterval))

	got := pathStats(t, store, path)
	want := PathStats{
		ActiveConnections: 1,
		TotalConnections:  1,
		TrafficCounters:   TrafficCounters{UploadBytes: 6000, DownloadBytes: 17000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path stats = %+v, want %+v", got, want)
	}
	history := pathStatsWithHistory(t, store, path).History
	if !reflect.DeepEqual(history, TrafficHistory{
		UploadBytesPerSecond:   []uint64{1200},
		DownloadBytesPerSecond: []uint64{3400},
	}) {
		t.Fatalf("traffic history = %+v", history)
	}

	store.sampleAt(windowStart.Add(2 * TrafficHistoryInterval))
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

	for sample := 1; sample <= TrafficHistorySampleCount+2; sample++ {
		connection.RecordUpload(uint64(sample) * uint64(TrafficHistoryInterval/time.Second))
		store.sampleAt(windowStart.Add(time.Duration(sample) * TrafficHistoryInterval))
	}
	history := pathStatsWithHistory(t, store, path).History.UploadBytesPerSecond
	want := make([]uint64, TrafficHistorySampleCount)
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

func TestTrafficHistoryAdd(t *testing.T) {
	var history TrafficHistory
	history.add(TrafficHistory{
		UploadBytesPerSecond:   []uint64{1, 2},
		DownloadBytesPerSecond: []uint64{3, 4},
	})
	history.add(TrafficHistory{
		UploadBytesPerSecond: []uint64{10, math.MaxUint64}, DownloadBytesPerSecond: []uint64{30, math.MaxUint64},
	})
	want := TrafficHistory{
		UploadBytesPerSecond: []uint64{11, math.MaxUint64}, DownloadBytesPerSecond: []uint64{33, math.MaxUint64},
	}
	if !reflect.DeepEqual(history, want) {
		t.Fatalf("aggregated history = %+v, want %+v", history, want)
	}
}

func TestPathStatsJSONRequiresHistoryAndFallback(t *testing.T) {
	payload, err := json.Marshal(PathStats{})
	if err != nil {
		t.Fatal(err)
	}
	var decoded PathStats
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.History, TrafficHistory{UploadBytesPerSecond: []uint64{}, DownloadBytesPerSecond: []uint64{}}) {
		t.Fatalf("decoded zero history = %+v", decoded.History)
	}
	for _, payload := range []string{
		`{"active_connections":0,"total_connections":0,"upload_bytes":0,"download_bytes":0,"history":{"upload_bytes_per_second":[],"download_bytes_per_second":[]}}`,
		`{"active_connections":0,"total_connections":0,"fallback_connections":0,"upload_bytes":0,"download_bytes":0}`,
		`{"active_connections":0,"total_connections":0,"fallback_connections":0,"upload_bytes":0,"download_bytes":0,"history":{"upload_bytes_per_second":[1],"download_bytes_per_second":[]}}`,
		`{"active_connections":0,"total_connections":0,"fallback_connections":0,"upload_bytes":0,"download_bytes":0,"history":{"upload_bytes_per_second":[],"download_bytes_per_second":[],"typo":true}}`,
	} {
		if err := json.Unmarshal([]byte(payload), &decoded); err == nil {
			t.Fatalf("accepted invalid path stats: %s", payload)
		}
	}
	tooMany := make([]uint64, TrafficHistorySampleCount+1)
	payload, err = json.Marshal(map[string]any{
		"active_connections": 0, "total_connections": 0, "fallback_connections": 0,
		"upload_bytes": 0, "download_bytes": 0,
		"history": map[string]any{"upload_bytes_per_second": tooMany, "download_bytes_per_second": tooMany},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &decoded); err == nil {
		t.Fatal("accepted too many traffic history samples")
	}
}

func TestStoreCountsFallbackConnections(t *testing.T) {
	path := trafficTestPath(t.Name())
	store := newStoreAt(time.Now())
	regular := store.OpenConnection(path, false)
	fallback := store.OpenConnection(path, true)
	regular.Close()
	fallback.Close()

	got := pathStats(t, store, path)
	if got.TotalConnections != 2 || got.FallbackConnections != 1 {
		t.Fatalf("connection counts = %+v", got)
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
		got := pathStats(t, store, path)
		if got.FallbackConnections > got.TotalConnections || got.ActiveConnections > got.TotalConnections {
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
	if err := failed.AttachExternalCounters(func() (TrafficCounters, error) {
		if readFails {
			return TrafficCounters{}, errors.New("read failed")
		}
		return TrafficCounters{UploadBytes: 100}, nil
	}); err != nil {
		t.Fatal(err)
	}
	healthy.RecordUpload(5000)
	store.sampleAt(windowStart.Add(TrafficHistoryInterval))
	if store.completedSamples != 1 {
		t.Fatalf("history count after failed refresh = %d, want 1", store.completedSamples)
	}
	if got := pathStatsWithHistory(t, store, healthyPath).History.UploadBytesPerSecond; !reflect.DeepEqual(got, []uint64{1000}) {
		t.Fatalf("healthy path history = %v, want [1000]", got)
	}

	readFails = false
	healthy.RecordUpload(5000)
	store.sampleAt(windowStart.Add(2 * TrafficHistoryInterval))
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
	store.sampleAt(windowStart.Add(TrafficHistoryInterval))

	got := pathStats(t, store, path)
	if got.ActiveConnections != 0 || got.TotalConnections != 1 ||
		got.TrafficCounters != (TrafficCounters{UploadBytes: 77, DownloadBytes: 88}) {
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
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{UploadBytes: 23, DownloadBytes: 12}, nil
	}); err != nil {
		t.Fatal(err)
	}

	got := pathStats(t, store, path)
	if got.TrafficCounters != (TrafficCounters{UploadBytes: 100, DownloadBytes: 100}) {
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
	store.sampleAt(windowStart.Add(TrafficHistoryInterval))

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
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{}, nil
	}); err == nil {
		t.Fatal("second external source was accepted")
	}
	connection.Close()
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{}, nil
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
	counters := TrafficCounters{UploadBytes: 10, DownloadBytes: 20}
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return counters, nil
	}); err != nil {
		t.Fatal(err)
	}
	store.Snapshot()
	counters.UploadBytes = 9
	if err := connection.Close(); err == nil {
		t.Fatal("external counter rollback was not reported")
	}
	if got := pathStats(t, store, trafficTestPath(t.Name())).TrafficCounters; got != (TrafficCounters{UploadBytes: 10, DownloadBytes: 20}) {
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
	store.sampleAt(windowStart.Add(TrafficHistoryInterval))

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
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{}, wantErr
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
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{}, wantErr
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
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	uploadFound := false
	fallbackFound := false
	for _, family := range families {
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	for i := 0; i < pathCount; i++ {
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
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				now = now.Add(TrafficHistoryInterval)
				store.sampleAt(now)
			}
		})
	}
}

var benchmarkTrafficSnapshot map[Path]PathStats

func BenchmarkTrafficSnapshot(b *testing.B) {
	for _, pathCount := range []int{1, 64, 256} {
		b.Run(fmt.Sprintf("paths=%d", pathCount), func(b *testing.B) {
			store, _ := benchmarkTrafficStore(pathCount)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
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
			source := func() (TrafficCounters, error) {
				return TrafficCounters{UploadBytes: 1, DownloadBytes: 1}, nil
			}
			for i := 0; i < connectionCount; i++ {
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
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				store.refreshExternalCounters()
			}
		})
	}
}
