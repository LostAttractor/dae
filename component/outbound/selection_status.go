// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"slices"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func (g *DialerGroup) NodeSelectionStatus(d *dialer.Dialer, runtime dialer.RuntimeSnapshot) *api.SelectionStatus {
	if !g.selectionPolicy.Automatic() {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	latency := candidateLatency(g.selectionPolicy.Policy, runtime.Latency)
	annotation := g.dialerToAnnotation[d]
	status := &api.SelectionStatus{
		Tracking: "standby", Degraded: runtime.Degraded, RecoveryElapsed: runtime.RecoveryElapsed, FailureRecovery: runtime.FailureRecovery,
		Priority: annotation.PriorityAt(latency), Score: saturatingDurationAdd(latency, annotation.AddLatency), MeasuredAt: runtime.MeasuredAt,
	}
	if runtime.CheckEnabled {
		status.Tracking = "monitoring"
	}
	if g.selector != nil && slices.Contains(g.selector.selected[:], d) {
		status.Tracking = "selected"
	}
	return status
}
