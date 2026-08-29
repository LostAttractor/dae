/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type statusSnapshotBuilder struct {
	plane       *ControlPlane
	connections connectionCountIndex
	traffic     trafficIndex
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func failureStatus(startedAt time.Time, duration time.Duration) *FailureStatus {
	if startedAt.IsZero() {
		return nil
	}
	return &FailureStatus{StartedAt: startedAt, DurationMs: duration.Milliseconds()}
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

func groupHealth(group GroupStatus, critical bool) HealthStatus {
	if group.Connectivity == nil {
		return HealthHealthy
	}
	switch group.Connectivity.State {
	case GroupConnectivityAvailable:
		return HealthHealthy
	case GroupConnectivityChecking:
		return HealthWarning
	}
	if critical {
		return HealthDegraded
	}
	return HealthWarning
}

func combineHealth(current, next HealthStatus) HealthStatus {
	if current == HealthDegraded || next == HealthDegraded {
		return HealthDegraded
	}
	if current == HealthWarning || next == HealthWarning {
		return HealthWarning
	}
	return HealthHealthy
}

func (b *statusSnapshotBuilder) networkStatuses() []NetworkConnectionStatus {
	statuses := make([]NetworkConnectionStatus, statusNetworkCount)
	for index := range statuses {
		counts := b.connections.byNetwork[index]
		statuses[index] = NetworkConnectionStatus{
			Network:     common.IndexToNetworkType(index).String(),
			ActiveConns: counts.active,
			TotalConns:  counts.total,
		}
	}
	return statuses
}

func (b *statusSnapshotBuilder) tableStatuses() []TableUsage {
	var tables []TableUsage
	if b.plane.dnsController != nil {
		tables = append(tables, TableUsage{
			Name:  "dns-cache",
			Used:  b.plane.dnsController.dnsCache.Len(),
			Limit: b.plane.dnsController.dnsCache.MaxSize(),
		})
	}
	if b.plane.core == nil || b.plane.core.domainRegistry == nil {
		return tables
	}

	usage := b.plane.core.domainRegistry.Usage()
	return append(tables,
		TableUsage{Name: "domain-kernel", Used: usage.KernelUsed, Limit: usage.KernelMax},
		TableUsage{
			Name:  "domain-history",
			Used:  usage.UserUsed,
			Limit: usage.UserMax,
			Breakdown: &TableUsageBreakdown{
				Live:     usage.UserLive,
				Retained: usage.UserRetained,
				LimitGC:  usage.LimitGC,
			},
		},
	)
}

func groupConnectivityStatus(group *outbound.DialerGroup) *GroupConnectivityStatus {
	if !group.ChecksConnectivity() {
		return nil
	}

	state, availability := group.Connectivity()
	recent := make([]GroupBucketState, len(availability.Recent.States))
	for index, state := range availability.Recent.States {
		recent[index] = GroupBucketState(state)
	}
	status := &GroupConnectivityStatus{
		State: GroupConnectivityState(state),
		Recent: GroupRecentStatus{
			WindowSeconds: int64(availability.Recent.Duration / time.Second),
			Buckets:       recent,
		},
		UpSince:     timePtr(availability.AliveSince),
		LastFailure: failureStatus(availability.LastFailureStartedAt, availability.LastFailureDuration),
	}
	if availability.Seen {
		status.UpRatio = &availability.UpRatio
		status.UpRatio24h = &availability.Recent24h.UpRatio
	}
	return status
}

func nodeAnnotationStatus(group *outbound.DialerGroup, node *dialer.Dialer) *NodeAnnotationStatus {
	annotation, ok := group.DialerAnnotation(node)
	if !ok {
		return nil
	}

	hasPriority := annotation.Priority != 0 ||
		len(annotation.PriorityTerms) > 0 ||
		len(annotation.ConditionalPriority) > 0
	if annotation.AddLatency == 0 && !hasPriority {
		return nil
	}

	status := &NodeAnnotationStatus{
		PriorityConditional: len(annotation.ConditionalPriority) > 0,
	}
	for _, term := range annotation.PriorityTerms {
		status.PriorityConditional = status.PriorityConditional || len(term.Conditional) > 0
	}
	if annotation.AddLatency != 0 {
		status.AddLatency = annotation.AddLatency.String()
	}
	if hasPriority {
		priority := annotation.Priority
		status.Priority = &priority
	}
	return status
}

func nodeSessionStatus(runtime dialer.RuntimeSnapshot) *SessionStatus {
	if !runtime.HasSession {
		return nil
	}
	status := &SessionStatus{
		State: SessionState(runtime.Session.State.String()),
		Seq:   runtime.Session.Seq,
	}
	if runtime.Session.Cause != nil {
		status.Error = runtime.Session.Cause.Error()
	}
	return status
}

func nodeNetworkStatuses(runtime dialer.RuntimeSnapshot) []NodeNetworkStatus {
	statuses := make([]NodeNetworkStatus, statusNetworkCount)
	for index := range statuses {
		statuses[index] = NodeNetworkStatus{
			Network:      common.IndexToNetworkType(index).String(),
			SupportState: NetworkSupportStatus(runtime.SupportState[index].String()),
		}
	}
	return statuses
}

func nodeHealthState(runtime dialer.RuntimeSnapshot) NodeHealthState {
	state := NodeHealthUnknown
	if runtime.Availability.Seen {
		state = NodeHealthUnhealthy
		if runtime.Healthy {
			state = NodeHealthHealthy
		}
	}
	if runtime.ConfirmingFailure {
		state = NodeHealthConfirming
	}
	return state
}

func nodeHealthStatus(
	group *outbound.DialerGroup,
	node *dialer.Dialer,
	runtime dialer.RuntimeSnapshot,
) *NodeHealthStatus {
	if !group.ChecksConnectivity() || !node.ChecksConnectivity() {
		return nil
	}

	availability := runtime.Availability
	status := &NodeHealthStatus{
		State:              nodeHealthState(runtime),
		UpRatio:            availability.UpRatio,
		UpRatio24h:         availability.Recent24h.UpRatio,
		HealthySince:       timePtr(availability.AliveSince),
		Failure:            failureStatus(availability.LastFailureStartedAt, availability.LastFailureDuration),
		LastCheckAt:        timePtr(availability.LastCheckAt),
		ChecksTotal:        availability.ChecksTotal,
		ChecksFailed:       availability.ChecksFailed,
		ChecksTotal24h:     availability.Recent24h.ChecksTotal,
		ChecksFailed24h:    availability.Recent24h.ChecksFailed,
		ChecksSinceHealthy: availability.ChecksSinceAlive,
	}
	if runtime.HasLatency {
		status.Latency = &LatencyStatus{
			LastMs:          milliseconds(runtime.Latency.Last),
			Average10Ms:     milliseconds(runtime.Latency.Avg10),
			MovingAverageMs: milliseconds(runtime.Latency.MovingAvg),
			Average10Failed: runtime.Latency.Avg10HasFailure,
		}
	}
	return status
}

func (b *statusSnapshotBuilder) nodeMetrics(
	groupName string,
	node NodeStatus,
	uniqueID bool,
) (connectionTotals, trafficValues) {
	if uniqueID {
		key := makeNodeIDKey(groupName, node.ID)
		return b.connections.byNodeID[key], b.traffic.byNodeID[key]
	}
	key := makeNodePathKey(groupName, node.ID, node.Subtag, node.Name)
	return b.connections.byNodePath[key], b.traffic.byNodePath[key]
}

func (b *statusSnapshotBuilder) nodeStatus(
	group *outbound.DialerGroup,
	node *dialer.Dialer,
	uniqueID bool,
) NodeStatus {
	runtime := node.RuntimeStatus()
	status := NodeStatus{
		ID:                      node.StatsID(),
		Name:                    node.Name,
		Subtag:                  node.Property.SubscriptionTag,
		Protocol:                node.Property.Protocol,
		Address:                 node.Property.Address,
		Hops:                    node.Property.Hops,
		Annotation:              nodeAnnotationStatus(group, node),
		CheckAsync:              node.InitialCheckMode() == dialer.InitialCheckAsync,
		Session:                 nodeSessionStatus(runtime),
		Health:                  nodeHealthStatus(group, node, runtime),
		Networks:                nodeNetworkStatuses(runtime),
		LastConnectionFailureAt: timePtr(runtime.Availability.LastConnFailAt),
	}
	connections, traffic := b.nodeMetrics(group.Name, status, uniqueID)
	status.ActiveConns = connections.active
	status.TotalConns = connections.total
	status.Traffic = trafficStatus(traffic)
	return status
}

func (b *statusSnapshotBuilder) groupNetworkStatus(
	group *outbound.DialerGroup,
	nodes []NodeStatus,
	networkIndex int,
) NetworkStatus {
	networkType := common.IndexToNetworkType(networkIndex)
	status := NetworkStatus{
		Network:      networkType.String(),
		SupportState: NetworkSupportUnsupported,
	}
	if selected := group.SelectedDialer(networkType); selected != nil {
		for index, candidate := range group.Dialers {
			if candidate == selected {
				status.Selected = &SelectedNodeStatus{Index: index}
				break
			}
		}
	}

	counts := b.connections.byGroupNetwork[groupNetworkKey{
		groupName:    group.Name,
		networkIndex: networkIndex,
	}]
	status.ActiveConns = counts.active
	status.TotalConns = counts.total
	for _, node := range nodes {
		switch node.Networks[networkIndex].SupportState {
		case NetworkSupportConfirmed:
			status.SupportState = NetworkSupportConfirmed
		case NetworkSupportUnknown:
			if status.SupportState != NetworkSupportConfirmed {
				status.SupportState = NetworkSupportUnknown
			}
		}
	}
	return status
}

func countNodeIDs(nodes []*dialer.Dialer) map[string]int {
	counts := make(map[string]int, len(nodes))
	for _, node := range nodes {
		counts[node.StatsID()]++
	}
	return counts
}

func (b *statusSnapshotBuilder) groupStatus(outboundIndex int, group *outbound.DialerGroup) GroupStatus {
	status := GroupStatus{
		Name:         group.Name,
		TargetKind:   group.TargetKind.String(),
		Policy:       group.DisplayPolicy(),
		Connectivity: groupConnectivityStatus(group),
		Nodes:        make([]NodeStatus, 0, len(group.Dialers)),
		Networks:     make([]NetworkStatus, statusNetworkCount),
		Traffic:      trafficStatus(b.traffic.byGroup[group.Name]),
	}

	nodeIDCounts := countNodeIDs(group.Dialers)
	for _, node := range group.Dialers {
		status.Nodes = append(status.Nodes, b.nodeStatus(group, node, nodeIDCounts[node.StatsID()] == 1))
	}
	for index := range status.Networks {
		status.Networks[index] = b.groupNetworkStatus(group, status.Nodes, index)
		status.ActiveConns += status.Networks[index].ActiveConns
	}

	critical := outboundIndex < len(b.plane.criticalOutbounds) && b.plane.criticalOutbounds[outboundIndex]
	status.Health = groupHealth(status, critical)
	return status
}

func (b *statusSnapshotBuilder) groupStatuses() ([]GroupStatus, HealthStatus) {
	health := HealthHealthy
	groups := make([]GroupStatus, 0, len(b.plane.outbounds))
	for outboundIndex, group := range b.plane.outbounds {
		if group.Kind == outbound.GroupKindInvisible {
			continue
		}
		status := b.groupStatus(outboundIndex, group)
		health = combineHealth(health, status.Health)
		groups = append(groups, status)
	}
	return groups, health
}

func (b *statusSnapshotBuilder) build(version string) *StatusSnapshot {
	groups, health := b.groupStatuses()
	return &StatusSnapshot{
		Version:      version,
		Health:       health,
		StartedAt:    stats.ProcessStart,
		LastReloadAt: timePtr(stats.LastReload()),
		ActiveConns:  b.connections.total.active,
		TotalConns:   b.connections.total.total,
		Traffic:      trafficStatus(b.traffic.global),
		Networks:     b.networkStatuses(),
		Tables:       b.tableStatuses(),
		Groups:       groups,
	}
}

func (c *ControlPlane) StatusSnapshot(version string) *StatusSnapshot {
	traffic := aggregateTrafficRates(stats.DefaultTrafficTracker.Snapshot())
	stats.DefaultTrafficTracker.FlushCounters()
	c.collectTrafficCounters(&traffic)
	builder := statusSnapshotBuilder{
		plane:       c,
		connections: c.collectConnectionCounts(),
		traffic:     traffic,
	}
	return builder.build(version)
}
