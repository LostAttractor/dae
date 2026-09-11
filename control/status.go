/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func (c *ControlPlane) tableStatuses() []api.TableUsage {
	var tables []api.TableUsage
	if c.core == nil || c.core.domainRegistry == nil {
		return tables
	}

	usage := c.core.domainRegistry.Usage()
	return append(tables,
		api.TableUsage{Name: "domain-kernel", Used: usage.KernelUsed, Limit: usage.KernelMax},
		api.TableUsage{
			Name:  "domain-history",
			Used:  usage.UserUsed,
			Limit: usage.UserMax,
			Breakdown: &api.TableUsageBreakdown{
				Live:     usage.UserLive,
				Retained: usage.UserRetained,
				LimitGC:  usage.LimitGC,
			},
		},
	)
}

func nodeAnnotationStatus(group *outbound.DialerGroup, node *dialer.Dialer) *api.NodeAnnotationStatus {
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

	status := &api.NodeAnnotationStatus{
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

func newNodeStatus(paths pathStatsIndex, group *outbound.DialerGroup, node *dialer.Dialer) api.NodeStatus {
	runtime := node.RuntimeStatus()
	status := api.NodeStatus{
		Revision:           runtime.Revision,
		ObservedSessionSeq: runtime.ObservedSessionSeq,
		Recovery: api.RecoverySnapshot{
			Executor: string(runtime.Recovery.Executor), Action: runtime.Recovery.Action,
			Phase: api.RecoveryPhase(runtime.Recovery.Phase), Verification: runtime.Recovery.Verification,
			Attempt: runtime.Recovery.Attempt, RetryAt: runtime.Recovery.RetryAt, BlockedBy: runtime.Recovery.BlockedBy,
		},
		ID:                 node.StatsID(),
		Name:               node.Name,
		Subtag:             node.Property.SubscriptionTag,
		Protocol:           node.Property.Protocol,
		Address:            node.Property.Address,
		Annotation:         nodeAnnotationStatus(group, node),
		ChecksConnectivity: node.ChecksConnectivity(),
		InitialCheckDone:   runtime.InitialCheckDone,
		Healthy:            runtime.Healthy,
		ConfirmingFailure:  runtime.ConfirmingFailure,
		Availability:       runtime.Availability,
		Support:            api.NetworkValues[api.NetworkSupportState](runtime.SupportState),
		Stats:              paths.nodes[groupNodeKey{group: group.Name, nodeID: node.StatsID()}],
	}
	if failure := runtime.Failure; failure != nil {
		status.Failure = &api.FailureSnapshot{
			EpisodeID: failure.EpisodeID, Resource: api.ResourceRef(failure.Resource),
			Scope: string(failure.Scope), Layer: string(failure.Layer), Phase: string(failure.Phase),
			Origin: string(failure.Origin), Reason: string(failure.Reason), Code: failure.Code,
			OccurredAt: failure.OccurredAt, Message: failure.Message,
		}
	}
	if runtime.HasSession {
		status.SessionDetail = &api.SessionStatus{
			State: runtime.Session.State.String(),
			Seq:   runtime.Session.Seq, ReadinessVersion: runtime.Session.ReadinessVersion,
			Resource: api.ResourceRef(runtime.Session.Resource), EpisodeID: runtime.Session.EpisodeID,
			Accepting: runtime.Session.Accepting, UsableCapacity: runtime.Session.UsableCapacity,
			RecoveryRequired: runtime.Session.RecoveryRequired,
		}
	}
	if runtime.HasLatency {
		latency := runtime.Latency
		status.Latency = &latency
	}
	return status
}

func newGroupStatus(paths pathStatsIndex, group *outbound.DialerGroup, critical bool) api.GroupStatus {
	pathStats := paths.groups[group.Name]
	status := api.GroupStatus{
		Name:               group.Name,
		TargetKind:         group.TargetKind.String(),
		Policy:             group.DisplayPolicy(),
		Critical:           critical,
		ChecksConnectivity: group.ChecksConnectivity(),
		CheckAsync:         group.CheckAsync,
		Stats:              pathStats.total,
		Networks:           api.NetworkValues[api.PathStats](pathStats.networks),
		Nodes:              make([]api.NodeStatus, 0, len(group.Dialers)),
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

// StatusSnapshot aggregates this plane's current runtime state. The caller must
// keep the plane alive until snapshot construction returns.
func (c *ControlPlane) StatusSnapshot(version string) *api.StatusSnapshot {
	paths := indexPathStats(stats.DefaultStore.SnapshotWithHistory())
	snapshot := &api.StatusSnapshot{
		Schema:       api.StatusSchemaVersion,
		Version:      version,
		StartedAt:    stats.DefaultStore.StartedAt(),
		LastReloadAt: stats.DefaultStore.LastReload(),
		Stats:        paths.total,
		Networks:     api.NetworkValues[api.PathStats](paths.networks),
		Tables:       c.tableStatuses(),
		Groups:       c.groupStatuses(paths),
	}
	snapshot.Plugins = c.MITMStatus()
	return snapshot
}

// GroupsStatus reads the current paths and their last observed connectivity.
// It does not select nodes or wait for connectivity checks.
func (c *ControlPlane) GroupsStatus() []api.GroupStatus {
	return c.groupStatuses(indexPathStats(stats.DefaultStore.SnapshotWithHistory()))
}

func (c *ControlPlane) groupStatuses(paths pathStatsIndex) []api.GroupStatus {
	groups := make([]api.GroupStatus, 0, len(c.outbounds))
	for index, group := range c.outbounds {
		if group.Kind == outbound.GroupKindInvisible {
			continue
		}
		critical := index < len(c.criticalOutbounds) && c.criticalOutbounds[index]
		groups = append(groups, newGroupStatus(paths, group, critical))
	}
	return groups
}
