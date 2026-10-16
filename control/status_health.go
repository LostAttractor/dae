// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func nodeHealthStatus(checks bool, runtime dialer.RuntimeSnapshot) api.NodeHealth {
	if !checks {
		return api.NodeHealthUnknown
	}
	if runtime.ConfirmingFailure {
		return api.NodeHealthConfirming
	}
	if !runtime.Availability.Seen {
		return api.NodeHealthUnknown
	}
	// Dormancy releases the physical transport without invalidating the most
	// recent observation. Readiness and probe activity remain separate fields.
	if runtime.Healthy || runtime.Dormant && runtime.ObservedHealthy {
		return api.NodeHealthHealthy
	}
	return api.NodeHealthUnhealthy
}

func groupHealthStatus(group api.GroupStatus) api.GroupHealth {
	if !group.ChecksConnectivity {
		return api.GroupHealthHealthy
	}
	if group.Connectivity == api.GroupStateAvailable {
		for network := range api.NetworkIndex(api.NetworkTypeCount) {
			if group.NetworkSupport(network) == api.NetworkSupportConfirmed && !group.NetworkRoutable(network) {
				return api.GroupHealthWarning
			}
		}
		return api.GroupHealthHealthy
	}
	if group.Connectivity == api.GroupStateChecking || !group.Critical {
		return api.GroupHealthWarning
	}
	return api.GroupHealthDegraded
}
