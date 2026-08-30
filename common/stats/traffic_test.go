/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"errors"
	"fmt"
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
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
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
	connection := store.OpenConnection(path)
	connection.RecordUpload(1200)
	connection.RecordDownload(3400)
	store.sampleAt(windowStart.Add(time.Second))

	got := pathStats(t, store, path)
	want := PathStats{
		ActiveConnections: 1,
		TotalConnections:  1,
		TrafficCounters:   TrafficCounters{UploadBytes: 1200, DownloadBytes: 3400},
		TrafficRate:       TrafficRate{UploadBytesPerSecond: 1200, DownloadBytesPerSecond: 3400},
	}
	if got != want {
		t.Fatalf("path stats = %+v, want %+v", got, want)
	}

	store.sampleAt(windowStart.Add(2 * time.Second))
	if got := pathStats(t, store, path).TrafficRate; got != (TrafficRate{}) {
		t.Fatalf("idle traffic rate = %+v, want zero", got)
	}
	connection.Close()
	got = pathStats(t, store, path)
	if got.ActiveConnections != 0 || got.TotalConnections != 1 {
		t.Fatalf("closed connection counts = %+v", got)
	}
}

func TestStoreUsesOneWindowForNewConnections(t *testing.T) {
	path := trafficTestPath(t.Name())
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	connection := store.OpenConnection(path)
	defer connection.Close()
	connection.RecordUpload(1000)

	store.sampleAt(windowStart.Add(time.Second))
	if got := pathStats(t, store, path).UploadBytesPerSecond; got != 1000 {
		t.Fatalf("first-window upload rate = %d, want 1000", got)
	}
}

func TestConnectionCloseKeepsShortConnectionTotals(t *testing.T) {
	path := trafficTestPath(t.Name())
	windowStart := time.Now()
	store := newStoreAt(windowStart)
	connection := store.OpenConnection(path)
	connection.RecordUpload(77)
	connection.RecordDownload(88)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	store.sampleAt(windowStart.Add(time.Second))

	got := pathStats(t, store, path)
	if got.ActiveConnections != 0 || got.TotalConnections != 1 ||
		got.TrafficCounters != (TrafficCounters{UploadBytes: 77, DownloadBytes: 88}) ||
		got.TrafficRate != (TrafficRate{UploadBytesPerSecond: 77, DownloadBytesPerSecond: 88}) {
		t.Fatalf("short connection stats = %+v", got)
	}
}

func TestSnapshotRefreshesActiveExternalCounters(t *testing.T) {
	path := trafficTestPath(t.Name())
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(path)
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
	connection := store.OpenConnection(path)
	connection.Close()
	connection.RecordUpload(77)
	store.sampleAt(windowStart.Add(time.Second))

	got := pathStats(t, store, path)
	if got.UploadBytes != 77 || got.UploadBytesPerSecond != 77 {
		t.Fatalf("late upload stats = %+v", got)
	}
}

func TestConnectionRejectsInvalidExternalSources(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()))
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
	connection := store.OpenConnection(trafficTestPath(t.Name()))
	counters := TrafficCounters{UploadBytes: 10, DownloadBytes: 20}
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return counters, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(); err != nil {
		t.Fatal(err)
	}
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
	connection := store.OpenConnection(path)
	want := uint64(1<<53 + 1)
	connection.RecordUpload(want)
	connection.Close()
	store.sampleAt(windowStart.Add(time.Second))

	got := pathStats(t, store, path)
	if got.UploadBytes != want || got.UploadBytesPerSecond != want {
		t.Fatalf("exact upload stats = %+v, want %d", got, want)
	}
}

func TestSnapshotReportsExternalReadFailure(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()))
	wantErr := errors.New("counter source failed")
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{}, wantErr
	}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.Snapshot()
	if !errors.Is(err, wantErr) {
		t.Fatalf("snapshot error = %v, want %v", err, wantErr)
	}
	if snapshot != nil {
		t.Fatalf("failed snapshot returned partial data: %+v", snapshot)
	}
	_ = connection.Close()
}

func TestConnectionCloseReportsFinalReadFailure(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()))
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
	connection := store.OpenConnection(path)
	connection.RecordUpload(42)
	connection.Close()
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "dae_traffic_bytes_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			direction := ""
			for _, label := range metric.GetLabel() {
				if label.GetName() == "direction" {
					direction = label.GetValue()
				}
			}
			if direction == trafficDirectionUpload && metric.GetCounter().GetValue() == 42 {
				return
			}
		}
	}
	t.Fatal("upload traffic metric was not gathered")
}

func TestConnectionRecordTrafficDoesNotAllocate(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()))
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
	connection := store.OpenConnection(trafficTestPath(b.Name()))
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
	connection := store.OpenConnection(path)
	_ = connection.Close()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		connection := store.OpenConnection(path)
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
		connection := store.OpenConnection(trafficTestPath(fmt.Sprintf("path-%d", i)))
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
				now = now.Add(time.Second)
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
				var err error
				benchmarkTrafficSnapshot, err = store.Snapshot()
				if err != nil {
					b.Fatal(err)
				}
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
				connection := store.OpenConnection(trafficTestPath(fmt.Sprintf("path-%d", i)))
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
				if err := store.refreshExternalCounters(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
