// SPDX-License-Identifier: AGPL-3.0-only
package surge

import "testing"

func TestSurgeScopeTranslation(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		port    uint16
		want    bool
	}{
		{"example.com", 443, true}, {"example.com", 80, true}, {"example.com:8443", 80, true},
		{"example.com:8443", 8443, true}, {"example.com:8443", 443, false},
		{"example.com", 8443, false}, {"example.com:0", 8443, true},
	} {
		scope, err := moduleScope([]string{tc.pattern})
		if err != nil {
			t.Fatal(err)
		}
		if got := scope.Match("example.com", tc.port); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
	scope, err := moduleScope([]string{"-private.example.com:8443", "*.example.com:0"})
	if err != nil {
		t.Fatal(err)
	}
	if scope.Match("private.example.com", 80) || scope.Match("private.example.com", 8443) || !scope.Match("private.example.com", 443) {
		t.Fatal("exclusion port translation lost ordering")
	}
	for _, pattern := range []string{"example.com:443junk", "example.com:65536", "[::1]:bad", "", "--example.com", "bad host", "https://example.com", "[::1]"} {
		if _, err := moduleScope([]string{pattern}); err == nil {
			t.Fatalf("accepted %s", pattern)
		}
	}
}
