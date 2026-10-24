// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/control"
)

type sharedStateFixture struct{ closes atomic.Int32 }

func (s *sharedStateFixture) Close() error { s.closes.Add(1); return nil }

type sharedStatePlugin struct {
	state   io.Closer
	release func() error
}

func (*sharedStatePlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *sharedStatePlugin) Close() error    { return p.release() }

func TestLoadMITMSharesRuntimeStatesAcrossGenerations(t *testing.T) {
	t.Setenv("DAE_LOCATION_CACHE", t.TempDir())
	runtime := control.NewRuntime()
	t.Cleanup(func() { _ = runtime.Close() })
	conf := mitmConfigForTest(t, `mitm { enabled: false } plugins { fixture { type: fixture } }`)
	definition := plugin.Definition{Configure: func(plugin.Spec) (plugin.Factory, error) {
		return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
			if services.SharedStates == nil {
				t.Fatal("daemon did not supply runtime shared states")
			}
			state, release, err := services.SharedStates.Acquire(ctx, "state", func() (io.Closer, error) { return new(sharedStateFixture), nil })
			if err != nil {
				return nil, err
			}
			return &sharedStatePlugin{state, release}, nil
		}, nil
	}}
	configured, err := configurePlugins(conf, map[string]plugin.Definition{"fixture": definition})
	if err != nil {
		t.Fatal(err)
	}
	load := func() *mitm.Host {
		t.Helper()
		// No previous host forces distinct plugin instances, as a changed config does.
		prepared, err := loadMITM(t.Context(), conf, nil, http.DefaultClient, http.DefaultClient, configured, nil, nil, runtime)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = prepared.Host.Close() })
		return prepared.Host
	}
	old, next := load(), load()
	oldInstance, nextInstance := old.Instances()[0], next.Instances()[0]
	if oldInstance == nextInstance {
		t.Fatal("fixture did not construct distinct plugin generations")
	}
	state := oldInstance.Plugin.(*sharedStatePlugin).state.(*sharedStateFixture)
	if nextInstance.Plugin.(*sharedStatePlugin).state != state {
		t.Fatal("daemon constructed independent state pools across generations")
	}
	if err := old.Close(); err != nil || state.closes.Load() != 0 {
		t.Fatalf("old host closed state still owned by next host: %v", err)
	}
	if err := next.Close(); err != nil || state.closes.Load() != 1 {
		t.Fatalf("last host did not close shared state: %v", err)
	}
}
