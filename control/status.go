/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type HealthStatus string

const (
	HealthHealthy  HealthStatus = "healthy"
	HealthWarning  HealthStatus = "warning"
	HealthDegraded HealthStatus = "degraded"
)

type StatusSnapshot struct {
	Version      string                    `json:"version"`
	Health       HealthStatus              `json:"health"` // aggregate connectivity of visible groups
	StartedAt    time.Time                 `json:"started_at"`
	LastReloadAt *time.Time                `json:"last_reload_at,omitempty"`
	ActiveConns  int64                     `json:"active_conns"`
	TotalConns   int64                     `json:"total_conns"`
	Networks     []NetworkConnectionStatus `json:"networks"`
	Tables       []TableUsage              `json:"tables"`
	Groups       []GroupStatus             `json:"groups"`
}

type NetworkConnectionStatus struct {
	Network     string `json:"network"`
	ActiveConns int64  `json:"active_conns"`
	TotalConns  int64  `json:"total_conns"`
}

// TableUsage is the fill level of one capacity-limited DNS/domain table.
type TableUsage struct {
	Name      string               `json:"name"`
	Used      int                  `json:"used"`
	Limit     int                  `json:"limit"`
	Breakdown *TableUsageBreakdown `json:"breakdown,omitempty"`
}

type TableUsageBreakdown struct {
	Live     int    `json:"live"`
	Retained int    `json:"retained"`
	LimitGC  uint64 `json:"limit_gc"`
}

type GroupStatus struct {
	Name         string                   `json:"name"`
	TargetKind   string                   `json:"target_kind"`
	Policy       string                   `json:"policy"`
	Health       HealthStatus             `json:"health"`                 // operational impact after applying group criticality
	Connectivity *GroupConnectivityStatus `json:"connectivity,omitempty"` // nil when the group has no connectivity checks
	Networks     []NetworkStatus          `json:"networks"`
	Nodes        []NodeStatus             `json:"nodes"`
	ActiveConns  int64                    `json:"active_conns"`
}

type GroupConnectivityStatus struct {
	State       GroupConnectivityState `json:"state"`
	UpRatio     *float64               `json:"up_ratio"`     // process-lifetime ratio; nil before the first observation
	UpRatio24h  *float64               `json:"up_ratio_24h"` // trailing 24-hour ratio; nil before the first observation
	Recent      GroupRecentStatus      `json:"recent"`
	UpSince     *time.Time             `json:"up_since,omitempty"`
	LastFailure *FailureStatus         `json:"last_failure,omitempty"`
}

type GroupRecentStatus struct {
	WindowSeconds int64              `json:"window_seconds"`
	Buckets       []GroupBucketState `json:"buckets"`
}

type NetworkStatus struct {
	Network      string               `json:"network"`
	SupportState NetworkSupportStatus `json:"support_state"`
	Selected     *SelectedNodeStatus  `json:"selected,omitempty"`
	ActiveConns  int64                `json:"active_conns"`
	TotalConns   int64                `json:"total_conns"`
}

type SelectedNodeStatus struct {
	Index int `json:"index"`
}

type SessionStatus struct {
	State SessionState `json:"state"`
	Seq   uint64       `json:"seq"`
	Error string       `json:"error,omitempty"`
}

type LatencyStatus struct {
	LastMs          float64 `json:"last_ms"`
	Average10Ms     float64 `json:"average_10_ms"`
	MovingAverageMs float64 `json:"moving_average_ms"`
	Average10Failed bool    `json:"average_10_failed"`
}

type NodeNetworkStatus struct {
	Network      string               `json:"network"`
	SupportState NetworkSupportStatus `json:"support_state"`
}

type FailureStatus struct {
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
}

type NodeHealthState string

type SessionState string

type NetworkSupportStatus string

type GroupConnectivityState string

type GroupBucketState string

const (
	NodeHealthUnknown    NodeHealthState = "unknown"
	NodeHealthHealthy    NodeHealthState = "healthy"
	NodeHealthConfirming NodeHealthState = "confirming"
	NodeHealthUnhealthy  NodeHealthState = "unhealthy"

	GroupConnectivityAvailable   GroupConnectivityState = "available"
	GroupConnectivityChecking    GroupConnectivityState = "checking"
	GroupConnectivityUnavailable GroupConnectivityState = "unavailable"

	GroupBucketUnknown     GroupBucketState = "unknown"
	GroupBucketAvailable   GroupBucketState = "available"
	GroupBucketUnavailable GroupBucketState = "unavailable"

	SessionDisconnected SessionState = "disconnected"
	SessionConnecting   SessionState = "connecting"
	SessionConnected    SessionState = "connected"
	SessionClosed       SessionState = "closed"

	NetworkSupportUnknown     NetworkSupportStatus = "unknown"
	NetworkSupportConfirmed   NetworkSupportStatus = "confirmed"
	NetworkSupportUnsupported NetworkSupportStatus = "unsupported"
)

type NodeStatus struct {
	ID                      string                `json:"id"`
	Name                    string                `json:"name"`
	Subtag                  string                `json:"subtag"`
	Protocol                string                `json:"protocol"`
	Address                 string                `json:"address"`
	Hops                    []dialer.Hop          `json:"hops,omitempty"`
	Annotation              *NodeAnnotationStatus `json:"annotation,omitempty"`
	CheckAsync              bool                  `json:"check_async,omitempty"`
	Session                 *SessionStatus        `json:"session,omitempty"`
	Health                  *NodeHealthStatus     `json:"health,omitempty"`
	Networks                []NodeNetworkStatus   `json:"networks"`
	LastConnectionFailureAt *time.Time            `json:"last_connection_failure_at,omitempty"`
	ActiveConns             int64                 `json:"active_conns"`
	TotalConns              int64                 `json:"total_conns"`
}

type NodeAnnotationStatus struct {
	AddLatency          string `json:"add_latency,omitempty"`
	Priority            *int   `json:"priority,omitempty"`
	PriorityConditional bool   `json:"priority_conditional,omitempty"`
}

type NodeHealthStatus struct {
	State              NodeHealthState `json:"state"`
	Latency            *LatencyStatus  `json:"latency,omitempty"`
	UpRatio            float64         `json:"up_ratio"`
	UpRatio24h         float64         `json:"up_ratio_24h"`
	HealthySince       *time.Time      `json:"healthy_since,omitempty"`
	Failure            *FailureStatus  `json:"failure,omitempty"`
	LastCheckAt        *time.Time      `json:"last_check_at,omitempty"`
	ChecksTotal        int64           `json:"checks_total"`
	ChecksFailed       int64           `json:"checks_failed"`
	ChecksTotal24h     int64           `json:"checks_total_24h"`
	ChecksFailed24h    int64           `json:"checks_failed_24h"`
	ChecksSinceHealthy int64           `json:"checks_since_healthy"`
}

type connValues struct{ active, total int64 }

func (v *connValues) add(active bool, value int64) {
	if active {
		v.active += value
	} else {
		v.total += value
	}
}

type groupNetworkKey struct {
	group   string
	network int
}

type groupNodeKey struct {
	group  string
	id     string
	subtag string
	name   string
}

type groupNodeIDKey struct {
	group string
	id    string
}

// connCounts is pre-aggregated once while gathering prometheus metrics. This
// keeps status rendering O(series + groups + nodes), rather than scanning all
// series again for every row.
type connCounts struct {
	all            connValues
	byNetwork      [4]connValues
	byGroupNetwork map[groupNetworkKey]connValues
	byGroupNode    map[groupNodeKey]connValues
	byGroupNodeID  map[groupNodeIDKey]connValues
}

func newConnCounts() connCounts {
	return connCounts{
		byGroupNetwork: make(map[groupNetworkKey]connValues),
		byGroupNode:    make(map[groupNodeKey]connValues),
		byGroupNodeID:  make(map[groupNodeIDKey]connValues),
	}
}

func (c *connCounts) add(group, id, subtag, name string, network int, active bool, value int64) {
	c.all.add(active, value)
	c.byNetwork[network].add(active, value)

	groupNetwork := groupNetworkKey{group: group, network: network}
	v := c.byGroupNetwork[groupNetwork]
	v.add(active, value)
	c.byGroupNetwork[groupNetwork] = v

	groupNode := groupNodeKey{group: group, id: id, subtag: subtag, name: name}
	v = c.byGroupNode[groupNode]
	v.add(active, value)
	c.byGroupNode[groupNode] = v

	groupNodeID := groupNodeIDKey{group: group, id: id}
	v = c.byGroupNodeID[groupNodeID]
	v.add(active, value)
	c.byGroupNodeID[groupNodeID] = v
}

func (c *ControlPlane) collectConnCounts() connCounts {
	counts := newConnCounts()
	families, _ := c.PrometheusRegistry.Gather()
	for _, family := range families {
		var active bool
		switch family.GetName() {
		case "dae_active_connections":
			active = true
		case "dae_total_connections":
			active = false
		default:
			continue
		}
		for _, metric := range family.GetMetric() {
			group, id, subtag, name, network := "", "", "", "", -1
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "id":
					id = label.GetValue()
				case "outbound":
					group = label.GetValue()
				case "subtag":
					subtag = label.GetValue()
				case "dialer":
					name = label.GetValue()
				case "network":
					for i := 0; i < 4; i++ {
						if common.IndexToNetworkType(i).String() == label.GetValue() {
							network = i
							break
						}
					}
				}
			}
			if network < 0 || group == "" || id == "" {
				continue
			}
			var value int64
			if active {
				if metric.GetGauge() == nil {
					continue
				}
				value = int64(metric.GetGauge().GetValue())
			} else {
				if metric.GetCounter() == nil {
					continue
				}
				value = int64(metric.GetCounter().GetValue())
			}
			counts.add(group, id, subtag, name, network, active, value)
		}
	}
	return counts
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func millis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func failureStatus(startedAt time.Time, duration time.Duration) *FailureStatus {
	if startedAt.IsZero() {
		return nil
	}
	return &FailureStatus{StartedAt: startedAt, DurationMs: duration.Milliseconds()}
}

func networkStatus(g *outbound.DialerGroup, index int, conns connCounts) NetworkStatus {
	networkType := common.IndexToNetworkType(index)
	ns := NetworkStatus{
		Network: networkType.String(),
	}
	if selected := g.SelectedDialer(networkType); selected != nil {
		for i, candidate := range g.Dialers {
			if candidate == selected {
				ns.Selected = &SelectedNodeStatus{Index: i}
				break
			}
		}
	}
	values := conns.byGroupNetwork[groupNetworkKey{group: g.Name, network: index}]
	ns.ActiveConns, ns.TotalConns = values.active, values.total
	return ns
}

func nodeStatus(g *outbound.DialerGroup, d *dialer.Dialer, conns connCounts, uniqueID bool) NodeStatus {
	runtime := d.RuntimeStatus()
	ns := NodeStatus{
		ID:         d.StatsID(),
		Name:       d.Name,
		Subtag:     d.Property.SubscriptionTag,
		Protocol:   d.Property.Protocol,
		Address:    d.Property.Address,
		Hops:       d.Property.Hops,
		CheckAsync: d.InitialCheckMode() == dialer.InitialCheckAsync,
		Networks:   make([]NodeNetworkStatus, 4),
	}
	if annotation, ok := g.DialerAnnotation(d); ok {
		hasPriority := annotation.Priority != 0 || len(annotation.PriorityTerms) != 0 || len(annotation.ConditionalPriority) != 0
		conditional := len(annotation.ConditionalPriority) != 0
		for _, term := range annotation.PriorityTerms {
			conditional = conditional || len(term.Conditional) != 0
		}
		if annotation.AddLatency != 0 || hasPriority {
			ns.Annotation = &NodeAnnotationStatus{
				PriorityConditional: conditional,
			}
			if annotation.AddLatency != 0 {
				ns.Annotation.AddLatency = annotation.AddLatency.String()
			}
			if hasPriority {
				priority := annotation.Priority
				ns.Annotation.Priority = &priority
			}
		}
	}
	if runtime.HasSession {
		session := runtime.Session
		ns.Session = &SessionStatus{State: SessionState(session.State.String()), Seq: session.Seq}
		if session.Cause != nil {
			ns.Session.Error = session.Cause.Error()
		}
	}
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		ns.Networks[i] = NodeNetworkStatus{
			Network:      networkType.String(),
			SupportState: NetworkSupportStatus(runtime.SupportState[i].String()),
		}
	}
	avail := runtime.Availability
	if g.ChecksConnectivity() && d.ChecksConnectivity() {
		ns.Health = &NodeHealthStatus{
			State:              NodeHealthUnknown,
			UpRatio:            avail.UpRatio,
			UpRatio24h:         avail.Recent24h.UpRatio,
			HealthySince:       timePtr(avail.AliveSince),
			Failure:            failureStatus(avail.LastFailureStartedAt, avail.LastFailureDuration),
			LastCheckAt:        timePtr(avail.LastCheckAt),
			ChecksTotal:        avail.ChecksTotal,
			ChecksFailed:       avail.ChecksFailed,
			ChecksTotal24h:     avail.Recent24h.ChecksTotal,
			ChecksFailed24h:    avail.Recent24h.ChecksFailed,
			ChecksSinceHealthy: avail.ChecksSinceAlive,
		}
		if avail.Seen {
			ns.Health.State = NodeHealthUnhealthy
			if runtime.Healthy {
				ns.Health.State = NodeHealthHealthy
			}
		}
		if runtime.ConfirmingFailure {
			ns.Health.State = NodeHealthConfirming
		}
		if runtime.HasLatency {
			ns.Health.Latency = &LatencyStatus{
				LastMs:          millis(runtime.Latency.Last),
				Average10Ms:     millis(runtime.Latency.Avg10),
				MovingAverageMs: millis(runtime.Latency.MovingAvg),
				Average10Failed: runtime.Latency.Avg10HasFailure,
			}
		}
	}
	ns.LastConnectionFailureAt = timePtr(avail.LastConnFailAt)
	values := conns.byGroupNodeID[groupNodeIDKey{group: g.Name, id: ns.ID}]
	if !uniqueID {
		values = conns.byGroupNode[groupNodeKey{
			group:  g.Name,
			id:     ns.ID,
			subtag: ns.Subtag,
			name:   ns.Name,
		}]
	}
	ns.ActiveConns, ns.TotalConns = values.active, values.total
	return ns
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

func (c *ControlPlane) StatusSnapshot(version string) *StatusSnapshot {
	conns := c.collectConnCounts()
	snapshot := &StatusSnapshot{
		Version:      version,
		Health:       HealthHealthy,
		StartedAt:    stats.ProcessStart,
		LastReloadAt: timePtr(stats.LastReload()),
	}
	snapshot.ActiveConns, snapshot.TotalConns = conns.all.active, conns.all.total
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		values := conns.byNetwork[i]
		snapshot.Networks = append(snapshot.Networks, NetworkConnectionStatus{
			Network:     networkType.String(),
			ActiveConns: values.active,
			TotalConns:  values.total,
		})
	}
	if c.dnsController != nil {
		snapshot.Tables = append(snapshot.Tables, TableUsage{
			Name:  "dns-cache",
			Used:  c.dnsController.dnsCache.Len(),
			Limit: c.dnsController.dnsCache.MaxSize(),
		})
	}
	if c.core != nil && c.core.domainRegistry != nil {
		usage := c.core.domainRegistry.Usage()
		snapshot.Tables = append(snapshot.Tables,
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
	for outboundID, g := range c.outbounds {
		if g.Kind == outbound.GroupKindInvisible {
			continue
		}
		gs := GroupStatus{
			Name:       g.Name,
			TargetKind: g.TargetKind.String(),
			Policy:     g.DisplayPolicy(),
			Networks:   make([]NetworkStatus, 4),
		}
		if g.ChecksConnectivity() {
			state, availability := g.Connectivity()
			recentStates := make([]GroupBucketState, len(availability.Recent.States))
			for i, state := range availability.Recent.States {
				recentStates[i] = GroupBucketState(state)
			}
			gs.Connectivity = &GroupConnectivityStatus{
				State: GroupConnectivityState(state),
				Recent: GroupRecentStatus{
					WindowSeconds: int64(availability.Recent.Duration / time.Second),
					Buckets:       recentStates,
				},
				UpSince:     timePtr(availability.AliveSince),
				LastFailure: failureStatus(availability.LastFailureStartedAt, availability.LastFailureDuration),
			}
			if availability.Seen {
				upRatio := availability.UpRatio
				upRatio24h := availability.Recent24h.UpRatio
				gs.Connectivity.UpRatio = &upRatio
				gs.Connectivity.UpRatio24h = &upRatio24h
			}
		}
		idCounts := make(map[string]int, len(g.Dialers))
		for _, d := range g.Dialers {
			idCounts[d.StatsID()]++
		}
		for _, d := range g.Dialers {
			gs.Nodes = append(gs.Nodes, nodeStatus(g, d, conns, idCounts[d.StatsID()] == 1))
		}
		for i := 0; i < 4; i++ {
			gs.Networks[i] = networkStatus(g, i, conns)
			gs.ActiveConns += gs.Networks[i].ActiveConns
			gs.Networks[i].SupportState = NetworkSupportUnsupported
			for _, node := range gs.Nodes {
				switch node.Networks[i].SupportState {
				case NetworkSupportConfirmed:
					gs.Networks[i].SupportState = NetworkSupportConfirmed
				case NetworkSupportUnknown:
					if gs.Networks[i].SupportState != NetworkSupportConfirmed {
						gs.Networks[i].SupportState = NetworkSupportUnknown
					}
				}
			}
		}
		critical := outboundID < len(c.criticalOutbounds) && c.criticalOutbounds[outboundID]
		gs.Health = groupHealth(gs, critical)
		snapshot.Health = combineHealth(snapshot.Health, gs.Health)
		snapshot.Groups = append(snapshot.Groups, gs)
	}
	return snapshot
}
