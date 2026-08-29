/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

func trafficTestIdentity(name string) TrafficIdentity {
	return TrafficIdentity{
		NodeID:   name,
		Outbound: name,
		Subtag:   "sub",
		Dialer:   "node",
		Network:  "tcp4",
	}
}

func deleteTrafficTestMetrics(identity TrafficIdentity) {
	for _, direction := range []string{TrafficDirectionUpload, TrafficDirectionDownload} {
		common.TrafficBytes.Delete(prometheus.Labels{
			"id":        identity.NodeID,
			"outbound":  identity.Outbound,
			"subtag":    identity.Subtag,
			"dialer":    identity.Dialer,
			"network":   identity.Network,
			"direction": direction,
		})
	}
}

func TestTrafficTrackerSamplesConnectionAndPublishesCounters(t *testing.T) {
	identity := trafficTestIdentity(t.Name())
	deleteTrafficTestMetrics(identity)
	t.Cleanup(func() { deleteTrafficTestMetrics(identity) })
	windowStart := time.Now()
	tracker := newTrafficTrackerAt(windowStart)
	connection := tracker.Open(identity)
	connection.RecordUpload(1200)
	connection.RecordDownload(3400)
	firstSampleAt := windowStart.Add(time.Second)
	tracker.sampleAt(firstSampleAt)

	snapshot := tracker.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Identity != identity {
		t.Fatalf("traffic snapshot = %+v", snapshot)
	}
	if got := snapshot[0].Rate; got != (TrafficRate{UploadBytesPerSecond: 1200, DownloadBytesPerSecond: 3400}) {
		t.Fatalf("traffic rate = %+v", got)
	}
	upload := common.TrafficBytes.With(prometheus.Labels{
		"id": identity.NodeID, "outbound": identity.Outbound, "subtag": identity.Subtag,
		"dialer": identity.Dialer, "network": identity.Network, "direction": TrafficDirectionUpload,
	})
	if got := metricValue(upload); got != 1200 {
		t.Fatalf("prometheus upload bytes = %v, want 1200", got)
	}

	tracker.sampleAt(firstSampleAt.Add(time.Second))
	if got := tracker.Snapshot()[0].Rate; got != (TrafficRate{}) {
		t.Fatalf("idle traffic rate = %+v, want zero", got)
	}
	connection.Close()
	if got := tracker.Snapshot(); len(got) != 0 {
		t.Fatalf("closed connection remains in snapshot: %+v", got)
	}
}

func TestTrafficConnectionExternalSourceStaysContinuousAfterDetach(t *testing.T) {
	identity := trafficTestIdentity(t.Name())
	deleteTrafficTestMetrics(identity)
	t.Cleanup(func() { deleteTrafficTestMetrics(identity) })
	windowStart := time.Now()
	tracker := newTrafficTrackerAt(windowStart)
	connection := tracker.Open(identity)
	defer connection.Close()
	firstSampleAt := windowStart.Add(time.Second)

	var upload, download atomic.Uint64
	connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{
			UploadBytes:   upload.Load(),
			DownloadBytes: download.Load(),
		}, nil
	})
	upload.Store(1000)
	download.Store(2000)
	tracker.sampleAt(firstSampleAt)
	if got := tracker.Snapshot()[0].Rate; got != (TrafficRate{UploadBytesPerSecond: 1000, DownloadBytesPerSecond: 2000}) {
		t.Fatalf("external traffic rate = %+v", got)
	}

	connection.DetachExternalCounters()
	connection.RecordUpload(500)
	connection.RecordDownload(250)
	upload.Store(9000)
	download.Store(9000)
	tracker.sampleAt(firstSampleAt.Add(time.Second))
	if got := tracker.Snapshot()[0].Rate; got != (TrafficRate{UploadBytesPerSecond: 500, DownloadBytesPerSecond: 250}) {
		t.Fatalf("post-detach traffic rate = %+v", got)
	}
}

func TestTrafficTrackerUsesOneWindowForNewConnections(t *testing.T) {
	identity := trafficTestIdentity(t.Name())
	deleteTrafficTestMetrics(identity)
	t.Cleanup(func() { deleteTrafficTestMetrics(identity) })
	windowStart := time.Now()
	tracker := newTrafficTrackerAt(windowStart)
	connection := tracker.Open(identity)
	defer connection.Close()
	connection.RecordUpload(1000)

	tracker.sampleAt(windowStart.Add(time.Second))
	if got := tracker.Snapshot()[0].Rate.UploadBytesPerSecond; got != 1000 {
		t.Fatalf("first-window upload rate = %d, want 1000", got)
	}
}

func TestTrafficConnectionCloseFlushesShortConnection(t *testing.T) {
	identity := trafficTestIdentity(t.Name())
	deleteTrafficTestMetrics(identity)
	t.Cleanup(func() { deleteTrafficTestMetrics(identity) })
	tracker := newTrafficTracker()
	connection := tracker.Open(identity)
	connection.RecordUpload(77)
	connection.RecordDownload(88)
	connection.Close()

	for direction, want := range map[string]float64{
		TrafficDirectionUpload: 77, TrafficDirectionDownload: 88,
	} {
		counter := common.TrafficBytes.With(prometheus.Labels{
			"id": identity.NodeID, "outbound": identity.Outbound, "subtag": identity.Subtag,
			"dialer": identity.Dialer, "network": identity.Network, "direction": direction,
		})
		if got := metricValue(counter); got != want {
			t.Fatalf("prometheus %s bytes = %v, want %v", direction, got, want)
		}
	}
}

func TestTrafficTrackerFlushesActiveConnectionCounters(t *testing.T) {
	identity := trafficTestIdentity(t.Name())
	deleteTrafficTestMetrics(identity)
	t.Cleanup(func() { deleteTrafficTestMetrics(identity) })
	tracker := newTrafficTracker()
	connection := tracker.Open(identity)
	defer connection.Close()
	connection.RecordUpload(77)
	connection.RecordDownload(88)
	connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{UploadBytes: 23, DownloadBytes: 12}, nil
	})

	tracker.FlushCounters()
	for direction, want := range map[string]float64{
		TrafficDirectionUpload: 100, TrafficDirectionDownload: 100,
	} {
		counter := common.TrafficBytes.With(prometheus.Labels{
			"id": identity.NodeID, "outbound": identity.Outbound, "subtag": identity.Subtag,
			"dialer": identity.Dialer, "network": identity.Network, "direction": direction,
		})
		if got := metricValue(counter); got != want {
			t.Fatalf("prometheus %s bytes = %v, want %v", direction, got, want)
		}
	}
}

func TestTrafficConnectionFlushesRecordRacingWithClose(t *testing.T) {
	identity := trafficTestIdentity(t.Name())
	deleteTrafficTestMetrics(identity)
	t.Cleanup(func() { deleteTrafficTestMetrics(identity) })
	connection := newTrafficTracker().Open(identity)
	connection.Close()
	connection.RecordUpload(77)

	counter := common.TrafficBytes.With(prometheus.Labels{
		"id": identity.NodeID, "outbound": identity.Outbound, "subtag": identity.Subtag,
		"dialer": identity.Dialer, "network": identity.Network, "direction": TrafficDirectionUpload,
	})
	if got := metricValue(counter); got != 77 {
		t.Fatalf("prometheus upload bytes = %v, want 77", got)
	}
}
