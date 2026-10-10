// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/certtest"
	"github.com/daeuniverse/dae/component/plugin"
)

// Control tests exercise the host contract without a concrete plugin runtime.
type controlTestPlugin struct {
	plan    plugin.Plan
	handle  func(*plugin.Exchange, plugin.Handler) (*http.Response, error)
	details any
}

func (p *controlTestPlugin) Plan() plugin.Plan { return p.plan }

func (p *controlTestPlugin) Wrap(_ plugin.Flow, next plugin.Handler) plugin.Handler {
	if p.handle == nil {
		return next
	}
	return func(e *plugin.Exchange) (*http.Response, error) { return p.handle(e, next) }
}

func (p *controlTestPlugin) Report() any { return p.details }

func mitmRoutingPlugin(hosts ...string) *controlTestPlugin {
	var scope plugin.Scope
	for _, host := range hosts {
		scope = append(scope, plugin.HostRule{Host: host, Ports: []uint16{80, 443}})
	}
	return &controlTestPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: scope, PreserveRoute: true}}}}
}

func rewriteTestPlugin(t *testing.T, targets map[string]string) *controlTestPlugin {
	t.Helper()
	urls := make(map[string]*url.URL)
	for path, target := range targets {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		urls[path] = u
	}
	p := mitmRoutingPlugin("original.example")
	p.plan.Scopes[0].PreserveRoute = false
	p.handle = func(e *plugin.Exchange, next plugin.Handler) (*http.Response, error) {
		if target := urls[e.Request.URL.Path]; target != nil {
			rewritten := *target
			e.Request.URL = &rewritten
			e.Request.Host = rewritten.Host
		}
		return next(e)
	}
	return p
}

func controlTestHost(t *testing.T, extension plugin.Plugin, authority *mitmca.Authority) *mitm.Host {
	t.Helper()
	if authority == nil && len(extension.Plan().Scopes) > 0 {
		authority = &mitmca.Authority{}
	}
	options := mitm.Options{Authority: authority}
	if diagnostic, ok := extension.(*certtest.Service); ok {
		options.Diagnostic = diagnostic
	}
	host, err := mitm.New(options, mitm.Instance{ID: "test", Type: "test", Plugin: extension})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host
}
