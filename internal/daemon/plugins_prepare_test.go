// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net/http"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

type deferredTestPlugin struct{}

func (*deferredTestPlugin) Plan() plugin.Plan { panic("live Plan must not run") }
func (*deferredTestPlugin) Close() error      { return nil }

func TestPluginPreparationDoesNotConstructInstances(t *testing.T) {
	t.Setenv("DAE_LOCATION_CACHE", t.TempDir())
	loadCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	builds := 0
	definition := plugin.Definition{
		Resources: func(ctx context.Context, _ plugin.Spec, services plugin.Services) (plugin.Resources, error) {
			if services.PrepareClient == nil || ctx.Err() != nil {
				t.Fatal("resources lost their preparation services")
			}
			return plugin.Resources{Plan: new(plugin.Plan)}, nil
		},
		Configure: func(plugin.Spec) (plugin.Factory, error) {
			return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
				builds++
				if ctx != t.Context() || ctx.Err() != nil || services.PrepareClient != nil {
					t.Fatal("factory retained the resource context or download client")
				}
				return new(deferredTestPlugin), nil
			}, nil
		},
	}
	conf := mitmConfigForTest(t, `plugins { fixture { type: fixture } }`)
	configuration, err := configurePlugins(conf, map[string]plugin.Definition{"fixture": definition})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := loadMITM(loadCtx, conf, nil, http.DefaultClient, nil, configuration, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Host != nil || prepared.BuildHost == nil || builds != 0 {
		t.Fatal("loading static resources constructed a live host")
	}
	cancel()
	for range 2 {
		if err := prepared.Build(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if prepared.Host == nil || builds != 1 {
		t.Fatalf("builds=%d, host=%v", builds, prepared.Host)
	}
	if err := prepared.Host.Close(); err != nil {
		t.Fatal(err)
	}
}
