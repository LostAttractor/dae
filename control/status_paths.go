/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
)

type groupPathStats struct {
	total    stats.PathStats
	networks [common.NetworkTypeCount]stats.PathStats
}

type groupNodeKey struct {
	group  string
	nodeID string
}

type pathStatsIndex struct {
	total    stats.PathStats
	networks [common.NetworkTypeCount]stats.PathStats
	groups   map[string]groupPathStats
	nodes    map[groupNodeKey]stats.PathStats
}

func indexPathStats(snapshot map[stats.Path]stats.PathStats) pathStatsIndex {
	index := pathStatsIndex{
		groups: make(map[string]groupPathStats),
		nodes:  make(map[groupNodeKey]stats.PathStats),
	}
	for path, values := range snapshot {
		if !path.Network.Valid() || path.Outbound == "" || path.NodeID == "" {
			continue
		}
		index.total.Add(values)
		index.networks[path.Network].Add(values)

		group := index.groups[path.Outbound]
		group.total.Add(values)
		group.networks[path.Network].Add(values)
		index.groups[path.Outbound] = group

		nodeKey := groupNodeKey{group: path.Outbound, nodeID: path.NodeID}
		node := index.nodes[nodeKey]
		node.Add(values)
		index.nodes[nodeKey] = node
	}
	return index
}
