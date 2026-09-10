// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/plugin"
)

func newScopeTestEngine(t *testing.T, sources ...string) *Engine {
	t.Helper()
	var modules []*Module
	for _, source := range sources {
		module, err := Parse(source, nil)
		if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, module)
	}
	// Selection does not use TLS or execute JavaScript; those paths have their
	// own integration tests and do not need to run for these scope assertions.
	engine, err := NewEngine(EngineOptions{BodyMemory: plugin.BodyMemory,
		Modules: modules, Runtime: &Runtime{},
		MaxBodySize: 1 << 20, MaxConcurrentScripts: 2, ScriptTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func assertScopeModules(t *testing.T, engine *Engine, host string, port uint16, want ...string) {
	t.Helper()
	var names []string
	for _, module := range engine.forConnection(host, port).options.Modules {
		names = append(names, module.Name)
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("connection %s:%d modules=%v, want %v", host, port, names, want)
	}
	if got := proxyTestHost(t, engine).Match(host, port) != mitm.HTTPBypass; got != (len(want) != 0) {
		t.Errorf("connection %s:%d Match=%t, want %t", host, port, got, len(want) != 0)
	}
}

func TestEngineScopeHostnamesRemainIndependent(t *testing.T) {
	first := "#!name=first\n[MITM]\nhostname=first.example\n"
	second := "#!name=second\n[MITM]\nhostname=second.example\n"
	for _, sources := range [][]string{{first, second}, {second, first}} {
		engine := newScopeTestEngine(t, sources...)
		assertScopeModules(t, engine, "first.example", 443, "first")
		assertScopeModules(t, engine, "SECOND.EXAMPLE.", 443, "second")
		assertScopeModules(t, engine, "unrelated.example", 443)
	}
}

func TestEngineScopeHostnameDirectivesApplyOnlyWithinModule(t *testing.T) {
	engine := newScopeTestEngine(t,
		"#!name=unrelated\n[MITM]\nhostname=outside.test\n",
		`#!name=directives
[MITM]
hostname=discarded.test
hostname=%APPEND% also-discarded.test
hostname=*.example
hostname=%APPEND% api.other:8443
hostname=%INSERT% -private.example
`,
	)
	assertScopeModules(t, engine, "outside.test", 443, "unrelated")
	assertScopeModules(t, engine, "public.example", 443, "directives")
	assertScopeModules(t, engine, "private.example", 443)
	assertScopeModules(t, engine, "api.other", 8443, "directives")
	assertScopeModules(t, engine, "discarded.test", 443)
	assertScopeModules(t, engine, "also-discarded.test", 443)
}

func TestEngineScopeExclusionDoesNotOverrideAnotherModule(t *testing.T) {
	wildcard := "#!name=wildcard\n[MITM]\nhostname=%INSERT% -private.example, *.example\n"
	private := "#!name=private\n[MITM]\nhostname=private.example\n"
	for _, sources := range [][]string{{wildcard, private}, {private, wildcard}} {
		engine := newScopeTestEngine(t, sources...)
		assertScopeModules(t, engine, "private.example", 443, "private")
		assertScopeModules(t, engine, "public.example", 443, "wildcard")
	}
	engine := newScopeTestEngine(t, wildcard)
	assertScopeModules(t, engine, "private.example", 443)
}

func TestEngineScopeConnectionPorts(t *testing.T) {
	engine := newScopeTestEngine(t,
		"#!name=default\n[MITM]\nhostname=default.example\n",
		"#!name=explicit\n[MITM]\nhostname=explicit.example:8443\n",
		"#!name=any\n[MITM]\nhostname=any.example:0\n",
		"#!name=shared443\n[MITM]\nhostname=shared.example\n",
		"#!name=shared8443\n[MITM]\nhostname=shared.example:8443\n",
	)
	assertScopeModules(t, engine, "default.example", 443, "default")
	assertScopeModules(t, engine, "default.example", 8443)
	assertScopeModules(t, engine, "explicit.example", 8443, "explicit")
	assertScopeModules(t, engine, "explicit.example", 443)
	assertScopeModules(t, engine, "any.example", 443, "any")
	assertScopeModules(t, engine, "any.example", 9443, "any")
	assertScopeModules(t, engine, "shared.example", 443, "shared443")
	assertScopeModules(t, engine, "shared.example", 8443, "shared8443")
	// Plain HTTP retains the existing hostname-only semantics even when a
	// module specifies a different TLS port.
	assertScopeModules(t, engine, "default.example", 80, "default")
	assertScopeModules(t, engine, "explicit.example", 80, "explicit")
	assertScopeModules(t, engine, "any.example", 80, "any")
	assertScopeModules(t, engine, "shared.example", 80, "shared443", "shared8443")
	assertScopeModules(t, engine, "", 443)
}

func TestEngineScopeMissingOrEmptyMITMDoesNotBorrowHostnames(t *testing.T) {
	engine := newScopeTestEngine(t,
		"#!name=allowed\n[MITM]\nhostname=app.bilibili.com\n",
		`#!name=missing
[Script]
wide=type=http-request,pattern=.,script-path=unused.js
[Rule]
DOMAIN,api.cloudflare.com,DIRECT
`,
		`#!name=empty
[MITM]
hostname=app.bilibili.com
hostname=
[Script]
wide=type=http-request,pattern=.,script-path=unused.js
[Rule]
DOMAIN,tracker.example,REJECT
`,
	)
	assertScopeModules(t, engine, "app.bilibili.com", 443, "allowed")
	assertScopeModules(t, engine, "app.bilibili.com", 80, "allowed")
	assertScopeModules(t, engine, "api.cloudflare.com", 443)
	assertScopeModules(t, engine, "tracker.example", 443)
	rules := engine.Plan().Routes
	if len(rules) != 2 || rules[0].Outbound.Name != "direct" || rules[0].AndFunctions[0].Params[0].Val != "api.cloudflare.com" || rules[1].Outbound.Name != "block" || rules[1].AndFunctions[0].Params[0].Val != "tracker.example" {
		t.Fatalf("HTTP scope filtering removed or changed module routing rules: %+v", rules)
	}
}
