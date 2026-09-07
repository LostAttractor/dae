// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"github.com/daeuniverse/dae/component/mitm"
	"testing"
)

func TestRequestRoutingIsModuleScoped(t *testing.T) {
	engine := newScopeTestEngine(t,
		"[MITM]\nhostname=pure.example\n",
		"[MITM]\nhostname=rewrite.example:8443\n[URL Rewrite]\n^https://rewrite.example/ http://new.example/ header\n",
		"[MITM]\nhostname=-private.script.example, *.script.example\n[Script]\nrequest=type=http-request,pattern=.,script-path=unused.js\n",
	)
	host := proxyTestHost(t, engine)
	for _, test := range []struct {
		host string
		port uint16
		want bool
	}{
		{"pure.example", 443, false}, {"rewrite.example", 8443, true}, {"rewrite.example", 443, false},
		{"api.script.example", 443, true}, {"private.script.example", 443, false}, {"outside.test", 443, false},
	} {
		if got := host.Match(test.host, test.port) == mitm.HTTPRequest; got != test.want {
			t.Errorf("%s:%d deferred=%v, want %v", test.host, test.port, got, test.want)
		}
	}
}
