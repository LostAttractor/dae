// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func testDefinition(prepare func(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error)) plugin.Definition {
	return plugin.Definition{Configure: func(spec plugin.Spec) (plugin.Factory, error) {
		return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
			return prepare(ctx, spec, services)
		}, nil
	}}
}

func loadTestPlugins(ctx context.Context, definitions map[string]plugin.Definition, specs []plugin.Spec, options Options, services plugin.Services) (*Host, error) {
	configured, err := Configure(definitions, specs)
	if err != nil {
		return nil, err
	}
	return configured.Load(ctx, options, services)
}

func TestConfigureChecksAllTypesBeforeParsing(t *testing.T) {
	called := false
	definitions := map[string]plugin.Definition{"known": {Configure: func(plugin.Spec) (plugin.Factory, error) {
		called = true
		return nil, nil
	}}, "incomplete": {}}
	_, err := Configure(definitions, []plugin.Spec{{ID: "first", Type: "known"}, {ID: "missing", Type: "unavailable"}, {ID: "nil_configure", Type: "incomplete"}})
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
	configured, err := Configure(definitions, []plugin.Spec{{ID: "first", Type: "checked"}, {ID: "middle", Type: "valid"}, {ID: "last", Type: "checked"}})
	if configured != nil || !errors.Is(err, invalid) || strings.Join(order, ",") != "first,last" || !strings.Contains(err.Error(), "plugins.first") || !strings.Contains(err.Error(), "plugins.last") {
		t.Fatalf("configuration: order=%v error=%v", order, err)
	}
}

func TestConfigureParsesOnceAndDefersResources(t *testing.T) {
	parsed, prepared := 0, 0
	definitions := map[string]plugin.Definition{"fixture": {Configure: func(plugin.Spec) (plugin.Factory, error) {
		parsed++
		return func(context.Context, plugin.Services) (plugin.Plugin, error) {
			prepared++
			return &testPlugin{}, nil
		}, nil
	}}}
	configured, err := Configure(definitions, []plugin.Spec{{ID: "one", Type: "fixture"}})
	if err != nil || parsed != 1 || prepared != 0 {
		t.Fatalf("configure: parsed=%d prepared=%d error=%v", parsed, prepared, err)
	}
	host, err := configured.Load(t.Context(), Options{}, plugin.Services{})
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
	old, next := load(4096), load(1024)
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
