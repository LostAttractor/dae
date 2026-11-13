// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func testDefinition(prepare func(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error)) plugin.Definition {
	return plugin.Definition{Resources: emptyPlanResources, Configure: func(spec plugin.Spec) (plugin.Factory, error) {
		return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
			return prepare(ctx, spec, services)
		}, nil
	}}
}

func loadTestPlugins(ctx context.Context, definitions map[string]plugin.Definition, specs []plugin.Spec, options Options, services plugin.Services) (*Host, error) {
	configured, err := pluginhost.Configure(definitions, specs)
	if err != nil {
		return nil, err
	}
	return Load(ctx, configured, options, services, nil)
}

func TestConfigureChecksAllTypesBeforeParsing(t *testing.T) {
	called := false
	definitions := map[string]plugin.Definition{"known": {Configure: func(plugin.Spec) (plugin.Factory, error) {
		called = true
		return nil, nil
	}}, "incomplete": {}}
	_, err := pluginhost.Configure(definitions, []plugin.Spec{{ID: "first", Type: "known"}, {ID: "missing", Type: "unavailable"}, {ID: "nil_configure", Type: "incomplete"}})
	if err == nil || called || !strings.Contains(err.Error(), "plugins.missing") || !strings.Contains(err.Error(), "plugins.nil_configure") {
		t.Fatalf("type preflight: called=%v error=%v", called, err)
	}
}

func TestConfigureAggregatesErrorsWithoutPreparing(t *testing.T) {
	invalid := errors.New("invalid configuration")
	var order []string
	definitions := map[string]plugin.Definition{"checked": {Configure: func(spec plugin.Spec) (plugin.Factory, error) {
		order = append(order, spec.ID)
		return nil, invalid
	}}, "valid": testDefinition(func(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error) {
		t.Fatal("preflight prepared resources")
		return nil, nil
	})}
	configured, err := pluginhost.Configure(definitions, []plugin.Spec{{ID: "first", Type: "checked"}, {ID: "middle", Type: "valid"}, {ID: "last", Type: "checked"}})
	if configured != nil || !errors.Is(err, invalid) || strings.Join(order, ",") != "first,last" || !strings.Contains(err.Error(), "plugins.first") || !strings.Contains(err.Error(), "plugins.last") {
		t.Fatalf("configuration: order=%v error=%v", order, err)
	}
}

func TestConfigureParsesOnceAndDefersResources(t *testing.T) {
	parsed, prepared := 0, 0
	definitions := map[string]plugin.Definition{"fixture": {Resources: emptyPlanResources, Configure: func(plugin.Spec) (plugin.Factory, error) {
		parsed++
		return func(context.Context, plugin.Services) (plugin.Plugin, error) {
			prepared++
			return &testPlugin{}, nil
		}, nil
	}}}
	configured, err := pluginhost.Configure(definitions, []plugin.Spec{{ID: "one", Type: "fixture"}})
	if err != nil || parsed != 1 || prepared != 0 {
		t.Fatalf("configure: parsed=%d prepared=%d error=%v", parsed, prepared, err)
	}
	host, err := Load(t.Context(), configured, Options{}, plugin.Services{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	if parsed != 1 || prepared != 1 {
		t.Fatalf("load reparsed configuration: parsed=%d prepared=%d", parsed, prepared)
	}
}

func TestHostInjectsSharedBodyBudgetAcrossReload(t *testing.T) {
	budget := membuffer.NewBudget(8192)
	definitions := map[string]plugin.Definition{"fixture": testDefinition(func(_ context.Context, _ plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
		if services.BodyMemory != budget {
			t.Fatal("factory did not receive the host's body budget")
		}
		return &testPlugin{}, nil
	})}
	load := func(limit int64) *Host {
		t.Helper()
		h, err := loadTestPlugins(t.Context(), definitions, []plugin.Spec{{ID: "one", Type: "fixture"}}, Options{BodyMemory: budget, BufferMemoryLimit: limit}, plugin.Services{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}
	old := load(4096)
	if err := old.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	next := load(1024)
	if budget.Status().Limit != 4096 {
		t.Fatal("candidate changed the active memory budget")
	}
	if err := next.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if budget.Status().Limit != 1024 {
		t.Fatal("overlapping hosts did not share the tighter budget")
	}
	if err := next.Close(); err != nil || budget.Status().Limit != 4096 {
		t.Fatalf("abandoned host did not release its budget limit: %v", err)
	}
	if err := old.Close(); err != nil || budget.Status().Limit != 8192 {
		t.Fatalf("host retirement leaked a budget limit: %v", err)
	}
}

func emptyPlanResources(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
	return plugin.Resources{Plan: new(plugin.Plan)}, nil
}

func TestStaticHostPlanMatchesBuiltHost(t *testing.T) {
	plan := plugin.Plan{
		RequiredOutbounds: []string{"direct"},
		DNS:               []plugin.DNSScope{{}},
		Scopes:            []plugin.HTTPScope{{Scope: testScope("example.test"), PreserveRoute: true}},
		EarlyRoutes:       []*config_parser.RoutingRule{{Outbound: config_parser.Function{Name: "block"}}},
		Routes:            []*config_parser.RoutingRule{{Outbound: config_parser.Function{Name: "direct"}}},
	}
	factories := 0
	definition := testDefinition(func(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error) {
		factories++
		return &testPlugin{plan: plan}, nil
	})
	definition.Resources = func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
		return plugin.Resources{Plan: &plan}, nil
	}
	configuration, err := pluginhost.Configure(map[string]plugin.Definition{"fixture": definition}, []plugin.Spec{{ID: "one", Type: "fixture"}, {ID: "two", Type: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := configuration.LoadResources(t.Context(), plugin.Services{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(t.Context(), prepared, Options{}, plugin.Services{}, nil); err == nil || factories != 0 {
		t.Fatal("missing authority was not rejected before factories")
	}
	if _, err := Build(t.Context(), prepared, Options{DisableHTTP: true, BufferMemoryLimit: -1}, plugin.Services{}, nil); err == nil || factories != 0 {
		t.Fatal("invalid buffer limit was not rejected before factories")
	}
	for _, disabled := range []bool{false, true} {
		options := Options{DisableHTTP: disabled, Authority: &localca.Authority{}}
		static, err := PreparePlan(options, prepared.Plan())
		if err != nil {
			t.Fatal(err)
		}
		if len(static.DNS) != 2 || len(static.EarlyRoutes) != 2 || len(static.Routes) != 2 || len(static.RequiredOutbounds) != 2 || (len(static.Scopes) == 0) != disabled {
			t.Fatalf("static aggregation/filter changed non-HTTP effects: %+v", static)
		}
		host, err := Build(t.Context(), prepared, options, plugin.Services{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = host.Close() })
		if !reflect.DeepEqual(static, host.Plan()) {
			t.Fatalf("built host plan differs from static plan: %+v != %+v", host.Plan(), static)
		}
	}
	if len(prepared.Plan().Scopes) != 2 || len(plan.Scopes) != 1 {
		t.Fatal("HTTP filtering mutated prepared declarations")
	}
}
