// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"fmt"
	"testing"
	"time"
)

// Keep a representative populated response for codec ablations.
func benchmarkStatus() StatusSnapshot {
	snapshot := StatusSnapshot{Schema: StatusSchemaVersion, Version: "benchmark", StartedAt: time.Unix(1, 0)}
	for groupID := range 10 {
		group := GroupStatus{Name: fmt.Sprint("group-", groupID), TargetKind: "group", ChecksConnectivity: true, Connectivity: GroupStateAvailable}
		group.Availability.Recent.States = make([]GroupHistoryState, GroupStateBucketCount)
		for i := range group.Availability.Recent.States {
			group.Availability.Recent.States[i] = GroupHistoryAvailable
		}
		for nodeID := range 20 {
			group.Nodes = append(group.Nodes, NodeStatus{ID: fmt.Sprint("node-", nodeID), Name: "example", Healthy: true,
				Support: NetworkValues[NetworkSupportState]{NetworkSupportConfirmed, NetworkSupportConfirmed, NetworkSupportConfirmed, NetworkSupportConfirmed},
				Latency: &LatencyStats{Last: 30 * time.Millisecond},
				Stats:   PathStats{History: TrafficHistory{UploadBytesPerSecond: make([]uint64, 12), DownloadBytesPerSecond: make([]uint64, 12)}},
			})
		}
		snapshot.Groups = append(snapshot.Groups, group)
	}
	return snapshot
}

func BenchmarkStatusDecode(b *testing.B) {
	payload, err := json.Marshal(benchmarkStatus(), jsonv1.FormatDurationAsNano(true))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		var snapshot StatusSnapshot
		if err := json.Unmarshal(payload, &snapshot, jsonv1.FormatDurationAsNano(true)); err != nil {
			b.Fatal(err)
		}
	}
}
