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
	Version     string        `json:"version"`
	StartedAt   time.Time     `json:"started_at"`
	ActiveConns int64         `json:"active_conns"`
	TotalConns  int64         `json:"total_conns"`
	ActiveByNet [4]int64      `json:"active_by_net"` // tcp4, tcp6, udp4, udp6
	Groups      []GroupStatus `json:"groups"`
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
	UpDuration         time.Duration `json:"up_duration"`
	AliveSince         *time.Time    `json:"alive_since,omitempty"`
	LastFailAt         *time.Time    `json:"last_fail_at,omitempty"`
	LastCheckAt        *time.Time    `json:"last_check_at,omitempty"`
	LastConnFailAt     *time.Time    `json:"last_conn_fail_at,omitempty"`
	ActiveConns        int64         `json:"active_conns"`
	TotalConns         int64         `json:"total_conns"`
}

// connCounts holds per-(group, node, network) connection counts collected
// from the prometheus vectors maintained by the data plane.
type connKey struct {
	group, subtag, node string
	network             int
}

type connValues struct{ active, total int64 }

type connCounts map[connKey]connValues

func (c connCounts) add(key connKey, active bool, value int64) {
	v := c[key]
	if active {
		v.active += value
	} else {
		v.total += value
	}
	c[key] = v
}

func (c connCounts) sum(match func(connKey) bool) (active, total int64) {
	for key, v := range c {
		if match(key) {
			active += v.active
			total += v.total
		}
	}
	return active, total
}

func (c *ControlPlane) collectConnCounts() connCounts {
	counts := make(connCounts)
	families, err := c.PrometheusRegistry.Gather()
	if err != nil {
		return counts
	}
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
			key := connKey{network: -1}
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "outbound":
					key.group = label.GetValue()
				case "subtag":
					key.subtag = label.GetValue()
				case "dialer":
					key.node = label.GetValue()
				case "network":
					for i := 0; i < 4; i++ {
						if common.IndexToNetworkType(i).String() == label.GetValue() {
							key.network = i
							break
						}
					}
				}
			}
			if key.network < 0 {
				continue
			}
			var value int64
			if active {
				value = int64(metric.GetGauge().GetValue())
			} else {
				value = int64(metric.GetCounter().GetValue())
			}
			counts.add(key, active, value)
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
	ns.ActiveConns, ns.TotalConns = conns.sum(func(k connKey) bool {
		return k.group == g.Name && k.network == index
	})
	return ns
}

func nodeStatus(g *outbound.DialerGroup, d *dialer.Dialer, conns connCounts) NodeStatus {
	ns := NodeStatus{
		Name:     d.Name,
		Subtag:   d.Property.SubscriptionTag,
		Protocol: d.Property.Protocol,
		Address:  d.Property.Address,
		Alive:    d.Alive(),
	}
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		ns.Supported[i] = d.Supported(networkType)
		ns.Selected[i] = g.SelectedDialer(networkType) == d
	}
	if last, avg10, movingAvg, ok := d.LatencySnapshot(g); ok {
		ns.HasLatency = true
		ns.LastLatencyMs = millis(last)
		ns.Avg10LatencyMs = millis(avg10)
		ns.MovingAvgLatencyMs = millis(movingAvg)
	}
	avail := stats.GetNode(d.StatsKey())
	ns.UpRatio = avail.UpRatio
	ns.UpDuration = avail.UpDuration
	ns.AliveSince = timePtr(avail.AliveSince)
	ns.LastFailAt = timePtr(avail.LastFailAt)
	ns.LastCheckAt = timePtr(avail.LastCheckAt)
	ns.LastConnFailAt = timePtr(avail.LastConnFailAt)
	ns.ActiveConns, ns.TotalConns = conns.sum(func(k connKey) bool {
		return k.group == g.Name && k.subtag == ns.Subtag && k.node == ns.Name
	})
	return ns
}

func (c *ControlPlane) StatusSnapshot(version string) *StatusSnapshot {
	conns := c.collectConnCounts()
	snapshot := &StatusSnapshot{
		Version:   version,
		StartedAt: stats.ProcessStart,
	}
	snapshot.ActiveConns, snapshot.TotalConns = conns.sum(func(connKey) bool { return true })
	for i := 0; i < 4; i++ {
		snapshot.ActiveByNet[i], _ = conns.sum(func(k connKey) bool { return k.network == i })
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
