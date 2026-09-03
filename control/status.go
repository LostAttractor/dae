/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func (c *ControlPlane) tableStatuses() []TableUsage {
	var tables []TableUsage
	if c.dnsController != nil {
		tables = append(tables, TableUsage{
			Name:  "dns-cache",
			Used:  c.dnsController.dnsCache.Len(),
			Limit: c.dnsController.dnsCache.MaxSize(),
		})
	}
	if c.core == nil || c.core.domainRegistry == nil {
		return tables
	}

	usage := c.core.domainRegistry.Usage()
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

func newNodeStatus(paths pathStatsIndex, group *outbound.DialerGroup, node *dialer.Dialer) NodeStatus {
	runtime := node.RuntimeStatus()
	status := NodeStatus{
		ID:                 node.StatsID(),
		Name:               node.Name,
		Subtag:             node.Property.SubscriptionTag,
		Protocol:           node.Property.Protocol,
		Address:            node.Property.Address,
		Annotation:         nodeAnnotationStatus(group, node),
		ChecksConnectivity: node.ChecksConnectivity(),
		CheckAsync:         node.InitialCheckMode() == dialer.InitialCheckAsync,
		Healthy:            runtime.Healthy,
		ConfirmingFailure:  runtime.ConfirmingFailure,
		Availability:       runtime.Availability,
		Support:            NetworkValues[dialer.NetworkSupportState](runtime.SupportState),
		Stats:              paths.nodes[groupNodeKey{group: group.Name, nodeID: node.StatsID()}],
	}
	if runtime.HasSession {
		status.Session = runtime.Session.State.String()
	}
	if runtime.HasLatency {
		latency := runtime.Latency
		status.Latency = &latency
	}
	return status
}

func newGroupStatus(paths pathStatsIndex, group *outbound.DialerGroup, critical bool) GroupStatus {
	pathStats := paths.groups[group.Name]
	status := GroupStatus{
		Name:               group.Name,
		TargetKind:         group.TargetKind.String(),
		Policy:             group.DisplayPolicy(),
		Critical:           critical,
		ChecksConnectivity: group.ChecksConnectivity(),
		Stats:              pathStats.total,
		Networks:           NetworkValues[stats.PathStats](pathStats.networks),
		Nodes:              make([]NodeStatus, 0, len(group.Dialers)),
	}
	if status.ChecksConnectivity {
		status.Connectivity, status.Availability = group.Connectivity()
	}
	for _, node := range group.Dialers {
		status.Nodes = append(status.Nodes, newNodeStatus(paths, group, node))
	}
	for index := common.NetworkIndex(0); index < common.NetworkTypeCount; index++ {
		if selected := group.SelectedDialer(index.NetworkType()); selected != nil {
			status.SelectedNodeIDs[index] = selected.StatsID()
		}
	}
	return status
}

func (c *ControlPlane) statusSnapshot(version string) *StatusSnapshot {
	paths := indexPathStats(stats.DefaultStore.SnapshotWithHistory())
	snapshot := &StatusSnapshot{
		Schema:       StatusSchemaVersion,
		Version:      version,
		StartedAt:    stats.DefaultStore.StartedAt(),
		LastReloadAt: stats.DefaultStore.LastReload(),
		Stats:        paths.total,
		Networks:     NetworkValues[stats.PathStats](paths.networks),
		Tables:       c.tableStatuses(),
		Groups:       make([]GroupStatus, 0, len(c.outbounds)),
	}
	for index, group := range c.outbounds {
		if group.Kind == outbound.GroupKindInvisible {
			continue
		}
		critical := index < len(c.criticalOutbounds) && c.criticalOutbounds[index]
		snapshot.Groups = append(snapshot.Groups, newGroupStatus(paths, group, critical))
	}
	return snapshot
}
