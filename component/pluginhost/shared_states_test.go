// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestSharedStateNamespaces(t *testing.T) {
	base := t.TempDir()
	type identity struct{ base, kind, id, key string }
	for _, test := range []struct {
		name   string
		a, b   identity
		shared bool
	}{
		{"normalized base", identity{base, "kind", "id", "state"}, identity{base + "/unused/..", "kind", "id", "state"}, true},
		{"different base", identity{base, "kind", "id", "state"}, identity{base + "/other", "kind", "id", "state"}, false},
		{"different type", identity{base, "kind", "id", "state"}, identity{base, "other", "id", "state"}, false},
		{"different instance", identity{base, "kind", "id", "state"}, identity{base, "kind", "other", "state"}, false},
		{"different state", identity{base, "kind", "id", "state"}, identity{base, "kind", "id", "other"}, false},
		{"type separator", identity{base, "kind:a", "b", "state"}, identity{base, "kind", "a:b", "state"}, false},
		{"key separator", identity{base, "kind", "a:b", "c"}, identity{base, "kind", "a", "b:c"}, false},
		{"empty base", identity{"", "kind", "id", "state"}, identity{"", "kind", "id", "state"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pool StatePool
			acquire := func(id identity) io.Closer {
				scoped, err := scopeStates(&pool, id.base, plugin.Spec{Type: id.kind, ID: id.id})
				if err != nil {
					t.Fatal(err)
				}
				value, release, err := scoped.Acquire(t.Context(), id.key, func() (io.Closer, error) { return new(poolTestState), nil })
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := release(); err != nil {
						t.Error(err)
					}
				})
				return value
			}
			if a, b := acquire(test.a), acquire(test.b); (a == b) != test.shared {
				t.Fatalf("shared = %v, want %v", a == b, test.shared)
			}
		})
	}
}

type leasedStatePlugin struct {
	state   io.Closer
	release func() error
}

func (*leasedStatePlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *leasedStatePlugin) Close() error    { return p.release() }

func TestPreparationSharesStatesAcrossOverlappingGenerations(t *testing.T) {
	var pool StatePool
	definition := plugin.Definition{Resources: emptyPlanResources, Configure: func(plugin.Spec) (plugin.Factory, error) {
		return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
			state, release, err := services.SharedStates.Acquire(ctx, "state", func() (io.Closer, error) { return new(poolTestState), nil })
			if err != nil {
				return nil, err
			}
			return &leasedStatePlugin{state, release}, nil
		}, nil
	}}
	configuration, err := Configure(map[string]plugin.Definition{"kind": definition}, []plugin.Spec{{Type: "kind", ID: "one"}, {Type: "kind", ID: "two"}})
	if err != nil {
		t.Fatal(err)
	}
	services := plugin.Services{BaseDir: t.TempDir(), SharedStates: &pool}
	first, err := configuration.Prepare(t.Context(), services, nil)
	if err != nil {
		t.Fatal(err)
	}
	same, err := configuration.Prepare(t.Context(), services, []*Instance{first[0].Instance, first[1].Instance})
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		if first[i].Instance != same[i].Instance {
			t.Fatal("unchanged instance was not reused")
		}
		if err := same[i].Release(); err != nil {
			t.Fatal(err)
		}
	}
	next, err := configuration.Prepare(t.Context(), services, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		oldState := first[i].Plugin.(*leasedStatePlugin).state.(*poolTestState)
		if next[i].Plugin.(*leasedStatePlugin).state != oldState {
			t.Fatal("overlapping generations constructed independent states")
		}
		if next[1-i].Plugin.(*leasedStatePlugin).state == oldState {
			t.Fatal("different instance acquired the same state")
		}
		if err := first[i].Release(); err != nil || oldState.closes.Load() != 0 {
			t.Fatalf("old generation closed shared state: %v", err)
		}
		if err := next[i].Release(); err != nil || oldState.closes.Load() != 1 {
			t.Fatalf("last generation did not close shared state: %v", err)
		}
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationFailureReleasesOwnedLeases(t *testing.T) {
	var pool StatePool
	failure := errors.New("factory failed")
	var states []*poolTestState
	definition := plugin.Definition{Resources: emptyPlanResources, Configure: func(spec plugin.Spec) (plugin.Factory, error) {
		return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
			state, release, err := services.SharedStates.Acquire(ctx, "state", func() (io.Closer, error) { return new(poolTestState), nil })
			if err != nil {
				return nil, err
			}
			states = append(states, state.(*poolTestState))
			if spec.ID == "broken" {
				// Factory errors own cleanup; no plugin exists for the host to close.
				return nil, errors.Join(failure, release())
			}
			return &leasedStatePlugin{state, release}, nil
		}, nil
	}}
	configuration, err := Configure(map[string]plugin.Definition{"kind": definition}, []plugin.Spec{{Type: "kind", ID: "ready"}, {Type: "kind", ID: "broken"}})
	if err != nil {
		t.Fatal(err)
	}
	instances, err := configuration.Prepare(t.Context(), plugin.Services{SharedStates: &pool}, nil)
	if !errors.Is(err, failure) || len(instances) != 0 || len(states) != 2 {
		t.Fatalf("Prepare = %v, %v; states = %d", instances, err, len(states))
	}
	for _, state := range states {
		if state.closes.Load() != 1 {
			t.Fatal("failed preparation leaked a lease")
		}
	}
	if len(pool.states) != 0 {
		t.Fatal("failed preparation retained closed states")
	}
}

func TestPreparationDoesNotReuseDifferentStatePool(t *testing.T) {
	definition := plugin.Definition{Resources: emptyPlanResources, Configure: func(plugin.Spec) (plugin.Factory, error) {
		return func(context.Context, plugin.Services) (plugin.Plugin, error) { return new(interfaceSourcePlugin), nil }, nil
	}}
	configuration, err := Configure(map[string]plugin.Definition{"kind": definition}, []plugin.Spec{{Type: "kind", ID: "one"}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := configuration.Prepare(t.Context(), plugin.Services{SharedStates: new(StatePool)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first[0].Release()
	next, err := configuration.Prepare(t.Context(), plugin.Services{SharedStates: new(StatePool)}, []*Instance{first[0].Instance})
	if err != nil {
		t.Fatal(err)
	}
	defer next[0].Release()
	if first[0].Instance == next[0].Instance {
		t.Fatal("instance retained another runtime's state pool")
	}
}
