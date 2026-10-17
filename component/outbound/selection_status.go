// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func (g *DialerGroup) NodeSelectionStatus(d *dialer.Dialer, runtime dialer.RuntimeSnapshot) *api.SelectionStatus {
	if !g.selectionPolicy.Automatic() {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	candidate := g.scoreCandidate(d, runtime.Latency, runtime.Degraded)
	status := &api.SelectionStatus{
		Tracking: "standby", Degraded: runtime.Degraded, RecoveryElapsed: runtime.RecoveryElapsed, FailureRecovery: runtime.FailureRecovery,
		Priority: candidate.priority, Score: candidate.sortingLatency, MeasuredAt: runtime.MeasuredAt,
	}
	if runtime.CheckEnabled {
		status.Tracking = "monitoring"
	}
	if g.automatic != nil && g.automatic.isSelected(d) {
		status.Tracking = "selected"
	}
	return status
}
