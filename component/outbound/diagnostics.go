// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"slices"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// ExplainSelection samples selection without creating a connection lease,
// waiting for checks, waking a transport or consuming randomness.
func (g *DialerGroup) ExplainSelection(network *common.NetworkType) api.ExplainOutbound {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := api.ExplainOutbound{Name: g.Name, Policy: g.DisplayPolicy(), Network: network.String(), ObservedAt: time.Now(), Nodes: make([]api.ExplainNode, 0, len(g.Dialers))}
	var selected *dialer.Dialer
	var randomCandidates []*dialer.Dialer
	result.Random = g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Random
	switch {
	case g.closed.Load():
	case result.Random:
		for _, candidate := range g.preferredRandomCandidates(network) {
			randomCandidates = append(randomCandidates, candidate.dialer)
		}
	case g.Kind != GroupKindSelector && len(g.Dialers) != 0:
		selected = g.Dialers[0]
	case g.selector != nil:
		selected = g.selector.selected[network.Index()]
	default:
		selected = g.fixedDialer()
	}
	for _, d := range g.Dialers {
		runtime := d.RuntimeStatus()
		node := api.ExplainNode{ID: d.StatsID(), Name: d.Name, Usable: !g.closed.Load() && g.selectionUsable(d, network), Selected: selected == d, Reason: "not_selected_by_policy"}
		if g.selectionPolicy.Automatic() {
			latency := candidateLatency(g.selectionPolicy.Policy, runtime.Latency)
			annotation := g.dialerToAnnotation[d]
			if annotation != nil {
				node.Selection = &api.SelectionStatus{Tracking: "standby", Priority: annotation.PriorityAt(latency), Score: saturatingDurationAdd(latency, annotation.AddLatency), MeasuredAt: runtime.MeasuredAt,
					Degraded: runtime.Degraded, RecoveryElapsed: runtime.RecoveryElapsed, FailureRecovery: runtime.FailureRecovery}
				if runtime.CheckEnabled {
					node.Selection.Tracking = "monitoring"
				}
				if node.Selected {
					node.Selection.Tracking = "selected"
				}
			}
		}
		switch {
		case !node.Usable:
			node.Reason = "unavailable_or_recovery_unverified"
		case node.Selected:
			node.Reason = "current_selection"
			result.Available = true
		case result.Random && slices.Contains(randomCandidates, d):
			node.Reason = "random_candidate"
			result.Available = true
		}
		result.Nodes = append(result.Nodes, node)
	}
	return result
}
