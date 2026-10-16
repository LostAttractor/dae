// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestNodeHealthObservation(t *testing.T) {
	for _, test := range []struct {
		name    string
		checks  bool
		runtime dialer.RuntimeSnapshot
		want    api.NodeHealth
	}{
		{"unchecked", false, dialer.RuntimeSnapshot{Healthy: true}, api.NodeHealthUnknown},
		{"unseen", true, dialer.RuntimeSnapshot{Healthy: true}, api.NodeHealthUnknown},
		{"confirming", true, dialer.RuntimeSnapshot{Healthy: true, ConfirmingFailure: true}, api.NodeHealthConfirming},
		{"healthy", true, dialer.RuntimeSnapshot{Healthy: true, Availability: api.Availability{Seen: true}}, api.NodeHealthHealthy},
		{"failed", true, dialer.RuntimeSnapshot{Availability: api.Availability{Seen: true}}, api.NodeHealthUnhealthy},
		{"dormant observation", true, dialer.RuntimeSnapshot{Dormant: true, ObservedHealthy: true, Availability: api.Availability{Seen: true}}, api.NodeHealthHealthy},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nodeHealthStatus(test.checks, test.runtime); got != test.want {
				t.Fatalf("health = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGroupHealthObservation(t *testing.T) {
	for _, test := range []struct {
		group api.GroupStatus
		want  api.GroupHealth
	}{
		{api.GroupStatus{}, api.GroupHealthHealthy},
		{api.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateAvailable}, api.GroupHealthHealthy},
		{api.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateChecking}, api.GroupHealthWarning},
		{api.GroupStatus{ChecksConnectivity: true, Connectivity: api.GroupStateUnavailable}, api.GroupHealthWarning},
		{api.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateUnavailable}, api.GroupHealthDegraded},
		{api.GroupStatus{ChecksConnectivity: true, Connectivity: api.GroupStateAvailable,
			Nodes: []api.NodeStatus{{Support: api.NetworkValues[api.NetworkSupportState]{api.NetworkSupportConfirmed}}}}, api.GroupHealthWarning},
	} {
		if got := groupHealthStatus(test.group); got != test.want {
			t.Fatalf("health(%+v) = %q, want %q", test.group, got, test.want)
		}
	}
}
