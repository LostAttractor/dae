// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/url"
	"testing"

	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/verify"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
)

// Control tests exercise the host contract without a concrete plugin runtime.
type controlTestPlugin struct {
	plan        plugin.Plan
	handle      func(*plugin.Exchange, plugin.Handler) (*plugin.Response, error)
	observeFlow func(plugin.Flow)
	details     any
}

func (p *controlTestPlugin) Plan() plugin.Plan { return p.plan }

func (p *controlTestPlugin) Wrap(flow plugin.Flow, next plugin.Handler) plugin.Handler {
	if p.observeFlow != nil {
		p.observeFlow(flow)
	}
	if p.handle == nil {
		return next
	}
	return func(e *plugin.Exchange) (*plugin.Response, error) { return p.handle(e, next) }
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
	p.handle = func(e *plugin.Exchange, next plugin.Handler) (*plugin.Response, error) {
		if target := urls[e.Request.Head.URL.Path]; target != nil {
			e.Request.Head.URL = target.Clone()
			e.Request.Head.Host = target.Host
		}
		return next(e)
	}
	return p
}

func testMITMAdmission(t *testing.T, host *mitm.Host) *mitm.Admission {
	t.Helper()
	admission, err := host.Admit()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admission.Release)
	return admission
}

func controlTestHost(t *testing.T, extension plugin.Plugin, authority *localca.Authority) *mitm.Host {
	t.Helper()
	if authority == nil && len(extension.Plan().Scopes) > 0 {
		authority = &localca.Authority{}
	}
	options := mitm.Options{Authority: authority}
	if diagnostic, ok := extension.(*mitmverify.Service); ok {
		options.Diagnostic = pluginhost.Adopt("test", "test", diagnostic)
		defer options.Diagnostic.Release()
	}
	host, err := mitm.New(options, mitm.Instance{ID: "test", Type: "test", Plugin: extension})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host
}
