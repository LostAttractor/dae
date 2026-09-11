// SPDX-License-Identifier: AGPL-3.0-only
package plugin

import "testing"

func TestExplicitScopePorts(t *testing.T) {
	scope := Scope{{Host: "Example.COM.", Ports: []uint16{8443}}}
	for _, port := range []uint16{0, 80, 443, 8443} {
		if got := scope.Match("example.com", port); got != (port == 8443) {
			t.Fatalf("port %d: %v", port, got)
		}
	}
	scope[0].Ports = nil
	if !scope.Match("example.com", 1234) || scope.Match("example.com", 0) {
		t.Fatal("wildcard port mismatch")
	}
}

func TestScopeOrdering(t *testing.T) {
	scope := Scope{
		{Host: "private.example.com", Ports: []uint16{443}, Exclude: true},
		{Host: "*.example.com", Ports: []uint16{80, 443}},
	}
	for _, tc := range []struct {
		host string
		port uint16
		want bool
	}{
		{"private.example.com", 443, false}, {"private.example.com", 80, true},
		{"public.example.com", 443, true}, {"example.com", 443, false}, {"other.test", 80, false},
	} {
		if got := scope.Match(tc.host, tc.port); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
	scope = Scope{{Host: "*"}, {Host: "private.example.com", Exclude: true}}
	if !scope.Match("private.example.com", 443) {
		t.Fatal("later exclusion overrode earlier match")
	}
	if !(Scope{{Host: "2001:db8::1", Ports: []uint16{443}}}).Match("2001:0db8::1", 443) {
		t.Fatal("IPv6 normalization failed")
	}
}
