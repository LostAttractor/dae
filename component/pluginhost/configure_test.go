// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"net/netip"
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
	definition := plugin.Definition{Configure: func(plugin.Spec) (plugin.Factory, error) {
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
	definition := plugin.Definition{Configure: func(plugin.Spec) (plugin.Factory, error) {
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
