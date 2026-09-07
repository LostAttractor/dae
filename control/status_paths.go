/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"math/bits"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
)

type groupPathStats struct {
	total    api.PathStats
	networks [common.NetworkTypeCount]api.PathStats
}

type groupNodeKey struct {
	group  string
	nodeID string
}

type pathStatsIndex struct {
	total    api.PathStats
	networks [common.NetworkTypeCount]api.PathStats
	groups   map[string]groupPathStats
	nodes    map[groupNodeKey]api.PathStats
}

func indexPathStats(snapshot map[stats.Path]api.PathStats) pathStatsIndex {
	index := pathStatsIndex{
		groups: make(map[string]groupPathStats),
		nodes:  make(map[groupNodeKey]api.PathStats),
	}
	for path, values := range snapshot {
		if !path.Network.Valid() || path.Outbound == "" || path.NodeID == "" {
			continue
		}
		addPathStats(&index.total, values)
		addPathStats(&index.networks[path.Network], values)

		group := index.groups[path.Outbound]
		addPathStats(&group.total, values)
		addPathStats(&group.networks[path.Network], values)
		index.groups[path.Outbound] = group

		nodeKey := groupNodeKey{group: path.Outbound, nodeID: path.NodeID}
		node := index.nodes[nodeKey]
		addPathStats(&node, values)
		index.nodes[nodeKey] = node
	}
	return index
}

// Values come from one store snapshot, with aligned traffic history samples.
func addPathStats(dst *api.PathStats, other api.PathStats) {
	dst.ActiveConnections += other.ActiveConnections
	dst.TotalConnections += other.TotalConnections
	dst.FallbackConnections += other.FallbackConnections
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
		sum, carry := bits.Add64(current[i], value, 0)
		if carry != 0 {
			sum = math.MaxUint64
		}
		current[i] = sum
	}
	return current
}
