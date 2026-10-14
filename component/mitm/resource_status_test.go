// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
)

type resourceStatusPlugin struct{ value int }

func (*resourceStatusPlugin) Plan() plugin.Plan           { return plugin.Plan{} }
func (p *resourceStatusPlugin) AcceptResources(value any) { p.value = value.(int) }

func TestReusedPluginPublishesOnlyAcceptedResourceStatus(t *testing.T) {
	p := new(resourceStatusPlugin)
	value := 1
	definition := plugin.Definition{
		Configure: func(plugin.Spec) (plugin.Factory, error) {
			return func(context.Context, plugin.Services) (plugin.Plugin, error) { return p, nil }, nil
		},
		Resources: func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
			return plugin.Resources{Key: "same-content", Value: value}, nil
		},
	}
	configuration, err := pluginhost.Configure(map[string]plugin.Definition{"fixture": definition}, []plugin.Spec{{ID: "fixture", Type: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	load := func(previous *Host) *Host {
		t.Helper()
		h, err := Load(t.Context(), configuration, Options{}, plugin.Services{}, previous)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}
	first := load(nil)
	if err := first.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	value = 2
	abandoned := load(first)
	if p.value != 1 {
		t.Fatal("preparation changed the active report")
	}
	if err := abandoned.Close(); err != nil {
		t.Fatal(err)
	}
	if p.value != 1 {
		t.Fatal("discarded metadata was published")
	}
	accepted := load(first)
	if !first.SameRuntime(accepted) {
		t.Fatal("metadata change replaced runtime")
	}
	accepted.CommitResources()
	if p.value != 2 {
		t.Fatal("unchanged runtime lost refreshed metadata")
	}
	suspended, err := first.PrepareSuccessor()
	if err != nil {
		t.Fatal(err)
	}
	defer suspended.Close()
	if err := suspended.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p.value != 2 {
		t.Fatal("suspend republished stale metadata")
	}
}
