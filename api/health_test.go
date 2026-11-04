// SPDX-License-Identifier: AGPL-3.0-only

package api

import "testing"

// A failing network keeps its confirmed capability but is not routable.
func TestFailingNetworkIsNotRoutable(t *testing.T) {
	node := NodeStatus{Healthy: true, Support: NetworkValues[NetworkSupportState]{
		NetworkSupportConfirmed, NetworkSupportConfirmed, NetworkSupportConfirmed, NetworkSupportConfirmed,
	}, Failing: NetworkValues[bool]{false, true, false, false}}
	group := GroupStatus{Policy: "min", Nodes: []NodeStatus{node}}
	if !group.NetworkRoutable(NetworkTCP4) || group.NetworkRoutable(NetworkTCP6) {
		t.Fatal("a failing network stayed routable or a serving one did not")
	}
	if group.NetworkSupport(NetworkTCP6) != NetworkSupportConfirmed {
		t.Fatal("failing dropped the confirmed capability")
	}
}
