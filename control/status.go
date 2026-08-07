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

type StatusSnapshot struct {
	Version      string        `json:"version"`
	StartedAt    time.Time     `json:"started_at"`
	LastReloadAt *time.Time    `json:"last_reload_at,omitempty"`
	ActiveConns  int64         `json:"active_conns"`
	TotalConns   int64         `json:"total_conns"`
	ActiveByNet  [4]int64      `json:"active_by_net"` // tcp4, tcp6, udp4, udp6
	Tables       []TableUsage  `json:"tables"`
	Groups       []GroupStatus `json:"groups"`
}

// TableUsage is the fill level of one capacity-limited DNS/domain table.
// Soft limits (LRU, memory-pressure GC) may be exceeded under churn; hard
// limits (eBPF map max_entries) cannot.
type TableUsage struct {
	Name  string `json:"name"`
	Used  int    `json:"used"`
	Limit int    `json:"limit"`
	Soft  bool   `json:"soft"`
}

type GroupStatus struct {
	Name     string           `json:"name"`
	Policy   string           `json:"policy"`
	NoCheck  bool             `json:"no_check"` // groups not subject to connectivity checks (direct)
	Networks [4]NetworkStatus `json:"networks"` // tcp4, tcp6, udp4, udp6
	Nodes    []NodeStatus     `json:"nodes"`
}

type NetworkStatus struct {
	Network     string     `json:"network"`
	Alive       bool       `json:"alive"`
	Selected    string     `json:"selected"` // dialer name, empty if none
	UpRatio     float64    `json:"up_ratio"`
	AliveSince  *time.Time `json:"alive_since,omitempty"`
	LastFailAt  *time.Time `json:"last_fail_at,omitempty"`
	ActiveConns int64      `json:"active_conns"`
	TotalConns  int64      `json:"total_conns"`
}

type NodeStatus struct {
	ID                 string        `json:"id"`
	Name               string        `json:"name"`
	Subtag             string        `json:"subtag"`
	Protocol           string        `json:"protocol"`
	Address            string        `json:"address"`
	Alive              bool          `json:"alive"`
	Supported          [4]bool       `json:"supported"`
	Selected           [4]bool       `json:"selected"`
	HasLatency         bool          `json:"has_latency"`
	LastLatencyMs      float64       `json:"last_latency_ms"`
	Avg10LatencyMs     float64       `json:"avg10_latency_ms"`
	MovingAvgLatencyMs float64       `json:"moving_avg_latency_ms"`
	UpRatio            float64       `json:"up_ratio"`
	UpRatio24h         float64       `json:"up_ratio_24h"`
	UpDuration         time.Duration `json:"up_duration"`
	AliveSince         *time.Time    `json:"alive_since,omitempty"`
	LastFailAt         *time.Time    `json:"last_fail_at,omitempty"`
	LastCheckAt        *time.Time    `json:"last_check_at,omitempty"`
	LastConnFailAt     *time.Time    `json:"last_conn_fail_at,omitempty"`
	ChecksTotal        int64         `json:"checks_total"`
	ChecksFailed       int64         `json:"checks_failed"`
	ChecksTotal24h     int64         `json:"checks_total_24h"`
	ChecksFailed24h    int64         `json:"checks_failed_24h"`
	ChecksSinceAlive   int64         `json:"checks_since_alive"`
	ChecksSinceFail    int64         `json:"checks_since_fail"`
	ActiveConns        int64         `json:"active_conns"`
	TotalConns         int64         `json:"total_conns"`
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
}

func newConnCounts() connCounts {
	return connCounts{
		byGroupNetwork: make(map[groupNetworkKey]connValues),
		byGroupNode:    make(map[groupNodeKey]connValues),
	}
}

func (c *connCounts) add(group, id string, network int, active bool, value int64) {
	c.all.add(active, value)
	c.byNetwork[network].add(active, value)

	groupNetwork := groupNetworkKey{group: group, network: network}
	v := c.byGroupNetwork[groupNetwork]
	v.add(active, value)
	c.byGroupNetwork[groupNetwork] = v

	groupNode := groupNodeKey{group: group, id: id}
	v = c.byGroupNode[groupNode]
	v.add(active, value)
	c.byGroupNode[groupNode] = v
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
			group, id, network := "", "", -1
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "id":
					id = label.GetValue()
				case "outbound":
					group = label.GetValue()
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
			counts.add(group, id, network, active, value)
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

func networkStatus(g *outbound.DialerGroup, index int, conns connCounts) NetworkStatus {
	networkType := common.IndexToNetworkType(index)
	avail := stats.GetGroup(g.Name, index)
	ns := NetworkStatus{
		Network:    networkType.String(),
		Alive:      avail.Alive,
		UpRatio:    avail.UpRatio,
		AliveSince: timePtr(avail.AliveSince),
		LastFailAt: timePtr(avail.LastFailAt),
	}
	if selected := g.SelectedDialer(networkType); selected != nil {
		ns.Selected = selected.Name
		ns.Alive = true
	}
	values := conns.byGroupNetwork[groupNetworkKey{group: g.Name, network: index}]
	ns.ActiveConns, ns.TotalConns = values.active, values.total
	return ns
}

func nodeStatus(g *outbound.DialerGroup, d *dialer.Dialer, conns connCounts) NodeStatus {
	runtime := d.RuntimeStatus(g)
	ns := NodeStatus{
		ID:        d.StatsID(),
		Name:      d.Name,
		Subtag:    d.Property.SubscriptionTag,
		Protocol:  d.Property.Protocol,
		Address:   d.Property.Address,
		Alive:     runtime.Alive,
		Supported: runtime.Supported,
	}
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		ns.Selected[i] = g.SelectedDialer(networkType) == d
	}
	if runtime.HasLatency {
		ns.HasLatency = true
		ns.LastLatencyMs = millis(runtime.Latency.Last)
		ns.Avg10LatencyMs = millis(runtime.Latency.Avg10)
		ns.MovingAvgLatencyMs = millis(runtime.Latency.MovingAvg)
	}
	avail := runtime.Availability
	ns.UpRatio = avail.UpRatio
	ns.UpDuration = avail.UpDuration
	ns.AliveSince = timePtr(avail.AliveSince)
	ns.LastFailAt = timePtr(avail.LastFailAt)
	ns.LastCheckAt = timePtr(avail.LastCheckAt)
	ns.LastConnFailAt = timePtr(avail.LastConnFailAt)
	ns.ChecksTotal = avail.ChecksTotal
	ns.ChecksFailed = avail.ChecksFailed
	ns.UpRatio24h = avail.Recent24h.UpRatio
	ns.ChecksTotal24h = avail.Recent24h.ChecksTotal
	ns.ChecksFailed24h = avail.Recent24h.ChecksFailed
	ns.ChecksSinceAlive = avail.ChecksSinceAlive
	ns.ChecksSinceFail = avail.ChecksSinceFail
	values := conns.byGroupNode[groupNodeKey{group: g.Name, id: ns.ID}]
	ns.ActiveConns, ns.TotalConns = values.active, values.total
	return ns
}

func (c *ControlPlane) StatusSnapshot(version string) *StatusSnapshot {
	conns := c.collectConnCounts()
	snapshot := &StatusSnapshot{
		Version:      version,
		StartedAt:    stats.ProcessStart,
		LastReloadAt: timePtr(stats.LastReload()),
	}
	snapshot.ActiveConns, snapshot.TotalConns = conns.all.active, conns.all.total
	for i := 0; i < 4; i++ {
		snapshot.ActiveByNet[i] = conns.byNetwork[i].active
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
			TableUsage{Name: "domain-verify", Used: usage.UserUsed, Limit: usage.UserMax, Soft: true},
			TableUsage{Name: "domain-kernel", Used: usage.KernelUsed, Limit: usage.KernelMax},
		)
	}
	for _, g := range c.outbounds {
		if g.Kind == outbound.GroupKindInvisible {
			continue
		}
		gs := GroupStatus{
			Name:    g.Name,
			Policy:  string(g.GetSelectionPolicy()),
			NoCheck: g.Kind == outbound.GroupKindAlwaysAlive,
		}
		for i := 0; i < 4; i++ {
			gs.Networks[i] = networkStatus(g, i, conns)
		}
		for _, d := range g.Dialers {
			gs.Nodes = append(gs.Nodes, nodeStatus(g, d, conns))
		}
		snapshot.Groups = append(snapshot.Groups, gs)
	}
	return snapshot
}
