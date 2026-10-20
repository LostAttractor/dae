// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"math"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
)

func TestPathStatsHistoryAggregation(t *testing.T) {
	var total api.PathStats
	addPathStats(&total, api.PathStats{History: api.TrafficHistory{
		UploadBytesPerSecond:   []uint64{1, 2},
		DownloadBytesPerSecond: []uint64{3, 4},
	}})
	addPathStats(&total, api.PathStats{History: api.TrafficHistory{
		UploadBytesPerSecond: []uint64{10, math.MaxUint64}, DownloadBytesPerSecond: []uint64{30, math.MaxUint64},
	}})
	want := api.TrafficHistory{
		UploadBytesPerSecond: []uint64{11, math.MaxUint64}, DownloadBytesPerSecond: []uint64{33, math.MaxUint64},
	}
	if !reflect.DeepEqual(total.History, want) {
		t.Fatalf("aggregated history = %+v, want %+v", total.History, want)
	}
}

func TestIndexTrafficStatsIncludesRetiredGroupTotals(t *testing.T) {
	snapshot := stats.TrafficSnapshot{
		Paths: map[stats.Path]api.PathStats{
			{NodeID: "current", Outbound: "proxy", Network: common.NetworkTCP4}: {TotalConnections: 1, UploadBytes: 50},
		},
		RetiredGroups: map[string][common.NetworkTypeCount]api.PathStats{"proxy": {{TotalConnections: 2, UploadBytes: 100}}},
		Networks:      [common.NetworkTypeCount]api.PathStats{{TotalConnections: 4, UploadBytes: 200}},
	}
	index := indexTrafficStats(snapshot)
	if index.total.UploadBytes != 200 || index.groups["proxy"].total.UploadBytes != 150 || index.nodes[groupNodeKey{group: "proxy", nodeID: "current"}].UploadBytes != 50 {
		t.Fatalf("aggregate counters leaked into node detail: %+v", index)
	}
}
