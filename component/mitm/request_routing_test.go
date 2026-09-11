// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"testing"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestRequestRoutingScopeContract(t *testing.T) {
	scope := testScope("-private.example", "*.example")
	for _, preserve := range []bool{false, true} {
		h := testHost(t, Options{Authority: &mitmca.Authority{}}, Instance{ID: "test", Plugin: &testPlugin{
			plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: scope, PreserveRoute: preserve}}},
		}})
		want := HTTPRequest
		if preserve {
			want = HTTPInspect
		}
		if h.Match("api.example", 443) != want || h.Match("private.example", 443) != HTTPBypass ||
			h.Match("api.example", 8443) != HTTPBypass || h.Match("outside.test", 443) != HTTPBypass {
			t.Fatal("routing effect changed scope semantics")
		}
	}
}

func TestOverlappingHTTPScopes(t *testing.T) {
	pure := plugin.HTTPScope{Scope: testScope("*.example"), PreserveRoute: true}
	request := plugin.HTTPScope{Scope: testScope("-private.example", "*.example")}
	for _, scopes := range [][]plugin.HTTPScope{{pure, request}, {request, pure}} {
		h := testHost(t, Options{Authority: &mitmca.Authority{}}, Instance{Plugin: &testPlugin{plan: plugin.Plan{Scopes: scopes}}})
		if h.Match("api.example", 443) != HTTPRequest {
			t.Fatal("pure inspection overrode a request-transforming scope")
		}
		if h.Match("private.example", 443) != HTTPInspect {
			t.Fatal("an exclusion erased another scope's independent allowance")
		}
	}
}
