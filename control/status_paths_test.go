// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
)

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
