/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	dto "github.com/prometheus/client_model/go"
)

const statusNetworkCount = 4

type connectionTotals struct {
	active int64
	total  int64
}

func (t *connectionTotals) add(active bool, value int64) {
	if active {
		t.active += value
		return
	}
	t.total += value
}

type groupNetworkKey struct {
	groupName    string
	networkIndex int
}

type nodePathKey struct {
	groupName  string
	nodeID     string
	subtag     string
	dialerName string
}

type nodeIDKey struct {
	groupName string
	nodeID    string
}

func makeNodePathKey(groupName, nodeID, subtag, dialerName string) nodePathKey {
	return nodePathKey{
		groupName:  groupName,
		nodeID:     nodeID,
		subtag:     subtag,
		dialerName: dialerName,
	}
}

func makeNodeIDKey(groupName, nodeID string) nodeIDKey {
	return nodeIDKey{groupName: groupName, nodeID: nodeID}
}

type trafficValues struct {
	rate     stats.TrafficRate
	counters stats.TrafficCounters
}

type trafficIndex struct {
	global     trafficValues
	byGroup    map[string]trafficValues
	byNodePath map[nodePathKey]trafficValues
	byNodeID   map[nodeIDKey]trafficValues
}

func newTrafficIndex() trafficIndex {
	return trafficIndex{
		byGroup:    make(map[string]trafficValues),
		byNodePath: make(map[nodePathKey]trafficValues),
		byNodeID:   make(map[nodeIDKey]trafficValues),
	}
}

func addTrafficRate[K comparable](index map[K]trafficValues, key K, rate stats.TrafficRate) {
	values := index[key]
	values.rate.Add(rate)
	index[key] = values
}

func addTrafficCounters[K comparable](index map[K]trafficValues, key K, counters stats.TrafficCounters) {
	values := index[key]
	values.counters.Add(counters)
	index[key] = values
}

func aggregateTrafficRates(snapshots []stats.TrafficSnapshot) trafficIndex {
	index := newTrafficIndex()
	for _, snapshot := range snapshots {
		identity := snapshot.Identity
		index.global.rate.Add(snapshot.Rate)
		addTrafficRate(index.byGroup, identity.Outbound, snapshot.Rate)
		addTrafficRate(index.byNodePath, makeNodePathKey(
			identity.Outbound,
			identity.NodeID,
			identity.Subtag,
			identity.Dialer,
		), snapshot.Rate)
		addTrafficRate(index.byNodeID, makeNodeIDKey(identity.Outbound, identity.NodeID), snapshot.Rate)
	}
	return index
}

func (i *trafficIndex) addCounters(labels statusMetricLabels, counters stats.TrafficCounters) {
	i.global.counters.Add(counters)
	addTrafficCounters(i.byGroup, labels.groupName, counters)
	addTrafficCounters(i.byNodePath, makeNodePathKey(
		labels.groupName,
		labels.nodeID,
		labels.subtag,
		labels.dialerName,
	), counters)
	addTrafficCounters(i.byNodeID, makeNodeIDKey(labels.groupName, labels.nodeID), counters)
}

func trafficStatus(values trafficValues) TrafficStatus {
	return TrafficStatus{
		WindowSeconds:          int64(stats.TrafficRateWindow / time.Second),
		UploadBytesPerSecond:   values.rate.UploadBytesPerSecond,
		DownloadBytesPerSecond: values.rate.DownloadBytesPerSecond,
		UploadBytes:            values.counters.UploadBytes,
		DownloadBytes:          values.counters.DownloadBytes,
	}
}

// connectionCountIndex is built once per status request so constructing rows
// does not repeatedly scan every Prometheus series.
type connectionCountIndex struct {
	total          connectionTotals
	byNetwork      [statusNetworkCount]connectionTotals
	byGroupNetwork map[groupNetworkKey]connectionTotals
	byNodePath     map[nodePathKey]connectionTotals
	byNodeID       map[nodeIDKey]connectionTotals
}

func newConnectionCountIndex() connectionCountIndex {
	return connectionCountIndex{
		byGroupNetwork: make(map[groupNetworkKey]connectionTotals),
		byNodePath:     make(map[nodePathKey]connectionTotals),
		byNodeID:       make(map[nodeIDKey]connectionTotals),
	}
}

func addConnectionCount[K comparable](index map[K]connectionTotals, key K, active bool, value int64) {
	total := index[key]
	total.add(active, value)
	index[key] = total
}

func (i *connectionCountIndex) add(labels statusMetricLabels, active bool, value int64) {
	i.total.add(active, value)
	i.byNetwork[labels.networkIndex].add(active, value)
	addConnectionCount(i.byGroupNetwork, groupNetworkKey{
		groupName:    labels.groupName,
		networkIndex: labels.networkIndex,
	}, active, value)
	addConnectionCount(i.byNodePath, makeNodePathKey(
		labels.groupName,
		labels.nodeID,
		labels.subtag,
		labels.dialerName,
	), active, value)
	addConnectionCount(i.byNodeID, makeNodeIDKey(labels.groupName, labels.nodeID), active, value)
}

type statusMetricLabels struct {
	groupName    string
	nodeID       string
	subtag       string
	dialerName   string
	networkIndex int
	direction    string
}

func networkIndex(network string) (int, bool) {
	for index := 0; index < statusNetworkCount; index++ {
		if common.IndexToNetworkType(index).String() == network {
			return index, true
		}
	}
	return 0, false
}

func parseStatusMetricLabels(metric *dto.Metric) (statusMetricLabels, bool) {
	labels := statusMetricLabels{networkIndex: -1}
	for _, label := range metric.GetLabel() {
		switch label.GetName() {
		case "id":
			labels.nodeID = label.GetValue()
		case "outbound":
			labels.groupName = label.GetValue()
		case "subtag":
			labels.subtag = label.GetValue()
		case "dialer":
			labels.dialerName = label.GetValue()
		case "network":
			if index, ok := networkIndex(label.GetValue()); ok {
				labels.networkIndex = index
			}
		case "direction":
			labels.direction = label.GetValue()
		}
	}
	valid := labels.networkIndex >= 0 && labels.groupName != "" && labels.nodeID != ""
	return labels, valid
}

func connectionMetricValue(familyName string, metric *dto.Metric) (active bool, value int64, ok bool) {
	switch familyName {
	case "dae_active_connections":
		if metric.GetGauge() == nil {
			return false, 0, false
		}
		return true, int64(metric.GetGauge().GetValue()), true
	case "dae_total_connections":
		if metric.GetCounter() == nil {
			return false, 0, false
		}
		return false, int64(metric.GetCounter().GetValue()), true
	default:
		return false, 0, false
	}
}

func (c *ControlPlane) collectConnectionCounts() connectionCountIndex {
	index := newConnectionCountIndex()
	families, _ := c.PrometheusRegistry.Gather()
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			active, value, ok := connectionMetricValue(family.GetName(), metric)
			if !ok {
				continue
			}
			labels, ok := parseStatusMetricLabels(metric)
			if !ok {
				continue
			}
			index.add(labels, active, value)
		}
	}
	return index
}

func trafficCounters(direction string, value uint64) (stats.TrafficCounters, bool) {
	switch direction {
	case stats.TrafficDirectionUpload:
		return stats.TrafficCounters{UploadBytes: value}, true
	case stats.TrafficDirectionDownload:
		return stats.TrafficCounters{DownloadBytes: value}, true
	default:
		return stats.TrafficCounters{}, false
	}
}

func (c *ControlPlane) collectTrafficCounters(index *trafficIndex) {
	families, _ := c.PrometheusRegistry.Gather()
	for _, family := range families {
		if family.GetName() != "dae_traffic_bytes_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metric.GetCounter() == nil {
				continue
			}
			labels, ok := parseStatusMetricLabels(metric)
			if !ok {
				continue
			}
			counters, ok := trafficCounters(labels.direction, uint64(metric.GetCounter().GetValue()))
			if !ok {
				continue
			}
			index.addCounters(labels, counters)
		}
	}
}
