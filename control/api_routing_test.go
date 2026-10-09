// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"testing"
)

func TestAPIRoutingAddressChanges(t *testing.T) {
	prepare := func(port uint16, addresses ...string) preparedRules {
		t.Helper()
		var addrs []net.Addr
		for _, address := range addresses {
			ip, subnet, err := net.ParseCIDR(address)
			if err != nil {
				t.Fatal(err)
			}
			subnet.IP = ip
			addrs = append(addrs, subnet)
		}
		var rules preparedRules
		rules.bypassAPI(port, addrs)
		return rules
	}
	old := prepare(8081, "192.0.2.1/24", "2001:db8::1/64")
	plane := &ControlPlane{apiPort: 8081, apiBypass: append(old.apiBypass, old.apiBypass...)}
	for _, test := range []struct {
		name      string
		port      uint16
		addresses []string
		current   bool
	}{
		{"same", 8081, []string{"192.0.2.1/24", "2001:db8::1/64"}, true},
		{"reordered and duplicated", 8081, []string{"2001:db8::1/64", "192.0.2.1/24", "192.0.2.1/32"}, true},
		{"subnet changed", 8081, []string{"192.0.2.1/32", "2001:db8::1/128"}, true},
		{"IPv4 replaced", 8081, []string{"192.0.2.2/24", "2001:db8::1/64"}, false},
		{"IPv6 replaced", 8081, []string{"192.0.2.1/24", "2001:db8::2/64"}, false},
		{"added", 8081, []string{"192.0.2.1/24", "2001:db8::1/64", "198.51.100.1/24"}, false},
		{"removed", 8081, []string{"192.0.2.1/24"}, false},
		{"empty", 8081, nil, false},
		{"port changed", 8082, []string{"192.0.2.1/24", "2001:db8::1/64"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := prepare(test.port, test.addresses...)
			if got := plane.matchesAPIBypass(current.apiBypass); got != test.current {
				t.Fatalf("API routing current=%v, want %v", got, test.current)
			}
		})
	}
	if current, err := new(ControlPlane).APIRoutingCurrent(); !current || err != nil {
		t.Fatalf("disabled TCP API required a routing refresh: %v, %v", current, err)
	}
}
