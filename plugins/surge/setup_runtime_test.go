// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/plugins/surge/internal/jq"
	log "github.com/sirupsen/logrus"
)

func TestPrepareWithoutScriptsNeedsNoRuntime(t *testing.T) {
	for name, module := range map[string]*Module{
		"empty":    {},
		"rewrite":  {URLRewrites: []URLRewrite{{Type: "reject"}}},
		"dns-host": {DNSHosts: []HostEntry{{}}},
	} {
		t.Run(name, func(t *testing.T) {
			e, err := prepare(t.Context(), Config{
				Store: true, NodePath: filepath.Join(t.TempDir(), "absent-node"),
				MemoryLimit: defaultMemoryLimit, MaxBodySize: defaultMaxBodySize,
				MaxConcurrentScripts: defaultMaxConcurrentScripts, ScriptTimeout: DefaultScriptTimeout,
			}, plugin.Services{Prepared: []*Module{module}, BodyMemory: testBodyMemory}, "test")
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.options.Runtime != nil || len(e.Status().Runtimes) != 0 {
				t.Fatal("script-free instance prepared a JavaScript runtime")
			}
		})
	}
}

func TestLoadedStaticPlanMatchesEngineWithoutEarlyStoreAccess(t *testing.T) {
	base := t.TempDir()
	for name, contents := range map[string]string{
		"rewrite.sgmodule": `[MITM]
hostname = -private.example.test:0,*.example.test:0
[Script]
request=type=http-request,pattern=.,script-path=request.js
[Host]
192.0.2.1=192.0.2.2
alias.example.test=192.0.2.3
[Rule]
DOMAIN,early.example.test,REJECT,pre-matching
DOMAIN,route.example.test,DIRECT
`,
		"inspect.sgmodule": "[MITM]\nhostname=inspect.test\n[Header Rewrite]\nhttp-response . header-add X-Test yes\n",
		"request.js":       "$done({});",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store := filepath.Join(base, "plugins", "test", "surge-store.json")
	if err := os.MkdirAll(filepath.Dir(store), 0700); err != nil {
		t.Fatal(err)
	}
	const untouched = "not valid JSON: preparation must not read this store"
	if err := os.WriteFile(store, []byte(untouched), 0600); err != nil {
		t.Fatal(err)
	}
	sections, err := config_parser.Parse("surge { http_policies: 'proxy, DIRECT' max_concurrent_scripts: 1 module { 'file:rewrite.sgmodule' 'file:inspect.sgmodule' } }")
	if err != nil {
		t.Fatal(err)
	}
	factories := 0
	definition := Plugin
	definition.Configure = func(spec plugin.Spec) (plugin.Factory, error) {
		factory, err := Configure(spec)
		return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
			factories++
			return factory(ctx, services)
		}, err
	}
	configuration, err := pluginhost.Configure(map[string]plugin.Definition{"surge": definition}, []plugin.Spec{{ID: "test", Type: "surge", Config: sections[0]}})
	if err != nil {
		t.Fatal(err)
	}
	services := plugin.Services{BaseDir: base, PrepareClient: http.DefaultClient}
	loadCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	prepared, err := configuration.LoadResources(loadCtx, services)
	if err != nil {
		t.Fatal(err)
	}
	plan := prepared.Plan()
	if factories != 0 || len(plan.RequiredOutbounds) != 2 || len(plan.DNS) != 1 || len(plan.Destinations) != 1 || len(plan.EarlyRoutes) != 1 || len(plan.Routes) != 1 || len(plan.Scopes) != 2 || plan.Scopes[0].PreserveRoute || !plan.Scopes[1].PreserveRoute {
		t.Fatalf("incomplete pre-factory plan: factories=%d plan=%+v", factories, plan)
	}
	if plan.Scopes[0].Match("private.example.test", 443) || !plan.Scopes[0].Match("public.example.test", 8443) {
		t.Fatal("static scope lost hostname exclusions or port matching")
	}
	cancel()
	services.BodyMemory = testBodyMemory
	instances, err := prepared.BuildInstances(t.Context(), services, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if len(instances) != 0 {
			_ = instances[0].Release()
		}
	})
	engine := instances[0].Plugin.(*Engine)
	if factories != 1 || !reflect.DeepEqual(plan, engine.Plan()) {
		t.Fatalf("static plan differs from live engine: %+v != %+v", plan, engine.Plan())
	}
	if err := instances[0].Release(); err != nil {
		t.Fatal(err)
	}
	// Release owns cleanup; prevent the test cleanup from releasing it twice.
	instances = nil
	if contents, err := os.ReadFile(store); err != nil || string(contents) != untouched {
		t.Fatalf("preparation read or rewrote the lazy store: %q, %v", contents, err)
	}
}

func TestResourceScopeErrorPrecedesFactory(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "invalid.sgmodule"), []byte("[MITM]\nhostname=example.test:65536\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sections, err := config_parser.Parse("surge { module { 'file:invalid.sgmodule' } }")
	if err != nil {
		t.Fatal(err)
	}
	definition := Plugin
	definition.Configure = func(spec plugin.Spec) (plugin.Factory, error) {
		_, err := Configure(spec)
		return func(context.Context, plugin.Services) (plugin.Plugin, error) {
			t.Fatal("invalid module scope reached Factory")
			return nil, nil
		}, err
	}
	configuration, err := pluginhost.Configure(map[string]plugin.Definition{"surge": definition}, []plugin.Spec{{ID: "invalid", Type: "surge", Config: sections[0]}})
	if err != nil {
		t.Fatal(err)
	}
	instances, err := configuration.Prepare(t.Context(), plugin.Services{BaseDir: base, PrepareClient: http.DefaultClient}, nil)
	if instances != nil || err == nil || !strings.Contains(err.Error(), "plugins.invalid resources") {
		t.Fatalf("invalid scope was not rejected during resource loading: %v, %v", instances, err)
	}
}

func TestStaticResourcesReleaseJQValidationPool(t *testing.T) {
	for _, hostname := range []string{"example.test", "example.test:65536"} {
		t.Run(hostname, func(t *testing.T) {
			pool, release, err := jq.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = release() })
			base := t.TempDir()
			module := "[MITM]\nhostname=" + hostname + "\n[Body Rewrite]\nhttp-response-jq . '.value=1'\n"
			if err := os.WriteFile(filepath.Join(base, "module.sgmodule"), []byte(module), 0600); err != nil {
				t.Fatal(err)
			}
			sections, err := config_parser.Parse("surge { module { 'file:module.sgmodule' } }")
			if err != nil {
				t.Fatal(err)
			}
			resources, err := prepareResources(t.Context(), plugin.Spec{Config: sections[0]}, plugin.Services{BaseDir: base, PrepareClient: http.DefaultClient, Logger: log.NewEntry(log.StandardLogger())})
			if (err != nil) != strings.Contains(hostname, ":") {
				t.Fatalf("unexpected scope validation result: %v", err)
			}
			if err == nil {
				modules := resources.Value.([]*Module)
				if resources.Plan == nil || len(resources.Plan.Scopes) != 1 || len(modules[0].BodyRewrites) != 1 || modules[0].BodyRewrites[0].jq != nil {
					t.Fatal("static resources retained a live jq pool or lost the rewrite")
				}
			}
			if err := release(); err != nil {
				t.Fatal(err)
			}
			if err := pool.Validate(t.Context(), "."); err == nil {
				t.Fatal("resource validation leaked a jq pool reference")
			}
		})
	}
}
