// SPDX-License-Identifier: AGPL-3.0-only

package api

type NodeHealth string

const (
	NodeHealthUnknown    NodeHealth = "unknown"
	NodeHealthHealthy    NodeHealth = "healthy"
	NodeHealthConfirming NodeHealth = "confirming"
	NodeHealthUnhealthy  NodeHealth = "unhealthy"
)

type GroupHealth string

const (
	GroupHealthHealthy  GroupHealth = "healthy"
	GroupHealthWarning  GroupHealth = "warning"
	GroupHealthDegraded GroupHealth = "degraded"
)

func (group GroupStatus) NetworkSupport(network NetworkIndex) NetworkSupportState {
	support := NetworkSupportUnsupported
	for _, node := range group.Nodes {
		switch node.Support[network] {
		case NetworkSupportConfirmed:
			return NetworkSupportConfirmed
		case NetworkSupportUnknown:
			support = NetworkSupportUnknown
		}
	}
	return support
}

func (group GroupStatus) NetworkRoutable(network NetworkIndex) bool {
	if group.SelectedNodeIDs[network] != "" {
		return true
	}
	if group.Policy == "" || group.Policy == "fixed" {
		return false
	}
	for _, node := range group.Nodes {
		if node.Healthy && node.Support[network] == NetworkSupportConfirmed {
			return true
		}
	}
	return false
}
