// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/plugin"
)

type interfaceSourcePlugin struct{ closed bool }

func (*interfaceSourcePlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *interfaceSourcePlugin) Close() error    { p.closed = true; return nil }

type testDeviceService struct{ id int }

func (*testDeviceService) Identify(context.Context, netip.Addr, [6]byte) [6]byte { return [6]byte{} }
func (*testDeviceService) MITMEnabled(context.Context) ([][6]byte, error)        { return nil, nil }

func TestPreparationReusesOnlyTheSameDeviceService(t *testing.T) {
	var received []plugin.DeviceService
	definition := plugin.Definition{Resources: emptyPlanResources, Configure: func(plugin.Spec) (plugin.Factory, error) {
		return func(_ context.Context, services plugin.Services) (plugin.Plugin, error) {
			received = append(received, services.Devices)
			return new(interfaceSourcePlugin), nil
		}, nil
	}}
	configuration, err := Configure(map[string]plugin.Definition{"fixture": definition}, []plugin.Spec{{ID: "a", Type: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	firstService, secondService := &testDeviceService{id: 1}, &testDeviceService{id: 2}
	var previous *Instance
	for i, service := range []plugin.DeviceService{nil, nil, firstService, firstService, secondService, nil} {
		var old []*Instance
		if previous != nil {
			old = []*Instance{previous}
		}
		prepared, err := configuration.Prepare(t.Context(), plugin.Services{Devices: service}, old)
		if err != nil {
			t.Fatal(err)
		}
		next := prepared[0].Instance
		wantReuse := i == 1 || i == 3
		if (next == previous) != wantReuse {
			t.Fatalf("step %d reuse = %v, want %v", i, next == previous, wantReuse)
		}
		if previous != nil {
			previous.Release()
		}
		previous = next
	}
	previous.Release()
	if len(received) != 4 || received[1] != firstService || received[2] != secondService {
		t.Fatalf("factory device services = %v", received)
	}
	if sameService([]int{1}, []int{1}) {
		t.Fatal("uncomparable services reused")
	}
}

func TestPreparationReusesOnlyTheSameInterfaceSource(t *testing.T) {
	var built []*interfaceSourcePlugin
	definition := plugin.Definition{Resources: emptyPlanResources, Configure: func(plugin.Spec) (plugin.Factory, error) {
		return func(context.Context, plugin.Services) (plugin.Plugin, error) {
			p := new(interfaceSourcePlugin)
			built = append(built, p)
			return p, nil
		}, nil
	}}
	configuration, err := Configure(map[string]plugin.Definition{"fixture": definition}, []plugin.Spec{{ID: "a", Type: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	services := plugin.Services{Interfaces: new(network.InterfaceManager)}
	first, err := configuration.Prepare(t.Context(), services, nil)
	if err != nil {
		t.Fatal(err)
	}
	same, err := configuration.Prepare(t.Context(), services, []*Instance{first[0].Instance})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Instance != same[0].Instance {
		t.Fatal("same source reconstructed plugin")
	}
	services.Interfaces = new(network.InterfaceManager)
	changed, err := configuration.Prepare(t.Context(), services, []*Instance{first[0].Instance})
	if err != nil {
		t.Fatal(err)
	}
	if changed[0].Instance == first[0].Instance || len(built) != 2 {
		t.Fatal("plugin kept a subscription to a different source")
	}
	first[0].Release()
	if built[0].closed {
		t.Fatal("shared plugin closed before old host drained")
	}
	same[0].Release()
	changed[0].Release()
	if !built[0].closed || !built[1].closed {
		t.Fatal("last owner did not close plugins")
	}
}

func emptyPlanResources(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
	return plugin.Resources{Plan: new(plugin.Plan)}, nil
}

// A prepared declaration must never be recovered from a running implementation.
type staticPlanPlugin struct{ interfaceSourcePlugin }

func (*staticPlanPlugin) Plan() plugin.Plan { panic("live Plan called") }

func TestResourcesExposePlanBeforeReusableInstanceBuild(t *testing.T) {
	loadCtx, cancelLoad := context.WithCancel(t.Context())
	defer cancelLoad()
	liveCtx := t.Context()
	var loads atomic.Int32
	var order []string
	var contexts []context.Context
	services := plugin.Services{BaseDir: t.TempDir(), SharedStates: new(StatePool)}
	definition := plugin.Definition{
		Resources: func(ctx context.Context, spec plugin.Spec, _ plugin.Services) (plugin.Resources, error) {
			loads.Add(1)
			return plugin.Resources{Key: spec.ID, Value: spec.ID, Plan: new(plugin.Plan{RequiredOutbounds: []string{spec.ID}})}, nil
		},
		Configure: func(spec plugin.Spec) (plugin.Factory, error) {
			return func(ctx context.Context, local plugin.Services) (plugin.Plugin, error) {
				order = append(order, spec.ID)
				contexts = append(contexts, ctx)
				if local.BaseDir != services.BaseDir || local.Prepared != spec.ID || local.Storage == nil || local.Metrics == nil || local.SharedStates == nil {
					t.Errorf("factory did not receive live services: %+v", local)
				}
				return new(staticPlanPlugin), nil
			}, nil
		},
	}
	configuration, err := Configure(map[string]plugin.Definition{"fixture": definition}, []plugin.Spec{{ID: "first", Type: "fixture"}, {ID: "last", Type: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := configuration.LoadResources(loadCtx, plugin.Services{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"first", "last"}
	if len(order) != 0 || !slices.Equal(prepared.Plan().RequiredOutbounds, want) {
		t.Fatalf("resource preparation ran factories or lost static order: %v %+v", order, prepared.Plan())
	}
	cancelLoad()
	first, err := prepared.BuildInstances(liveCtx, services, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := make([]*Instance, len(first))
	for i, instance := range first {
		previous[i] = instance.Instance
		t.Cleanup(func() { _ = instance.Release() })
		if !reflect.DeepEqual(instance.Plan, plugin.Plan{RequiredOutbounds: want[i : i+1]}) {
			t.Fatal("instance did not receive the static declaration")
		}
	}
	for _, prior := range [][]*Instance{previous, nil} {
		next, err := prepared.BuildInstances(liveCtx, services, prior)
		if err != nil {
			t.Fatal(err)
		}
		for i, instance := range next {
			t.Cleanup(func() { _ = instance.Release() })
			if (instance.Instance == previous[i]) != (prior != nil) {
				t.Fatal("prepared inputs changed instance reuse")
			}
		}
	}
	if loads.Load() != 2 || !slices.Equal(order, []string{"first", "last", "first", "last"}) {
		t.Fatalf("reusable build reloaded resources or changed factory order: loads=%d order=%v", loads.Load(), order)
	}
	for _, ctx := range contexts {
		if ctx != liveCtx || ctx.Err() != nil {
			t.Fatal("factory retained the resource loading context")
		}
	}
}

func TestMissingStaticPlanRejectsBeforeFactories(t *testing.T) {
	failure := errors.New("bad resource")
	for _, test := range []struct {
		name      string
		resources func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error)
		message   string
	}{
		{"missing capability", nil, "static Plan declaration is required"},
		{"missing declaration", func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
			return plugin.Resources{}, nil
		}, "no static Plan declaration"},
		{"resource error", func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
			return plugin.Resources{}, failure
		}, failure.Error()},
	} {
		t.Run(test.name, func(t *testing.T) {
			definition := plugin.Definition{Resources: test.resources, Configure: func(plugin.Spec) (plugin.Factory, error) {
				return func(context.Context, plugin.Services) (plugin.Plugin, error) {
					t.Fatal("factory ran before all resources and declarations were validated")
					return nil, nil
				}, nil
			}}
			valid := definition
			valid.Resources = emptyPlanResources
			configuration, err := Configure(map[string]plugin.Definition{"valid": valid, "invalid": definition}, []plugin.Spec{{ID: "first", Type: "valid"}, {ID: "bad", Type: "invalid"}})
			if err != nil {
				t.Fatal(err)
			}
			instances, err := configuration.Prepare(t.Context(), plugin.Services{}, nil)
			if len(instances) != 0 || err == nil || !strings.Contains(err.Error(), "plugins.bad") || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Prepare = %v, %v", instances, err)
			}
		})
	}
}
