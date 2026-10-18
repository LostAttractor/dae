// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestPrepareParallelResourcesPreserveFactoryOrderAndContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var factories []string
	var factoryContexts []context.Context
	definition := plugin.Definition{
		Resources: func(ctx context.Context, spec plugin.Spec, services plugin.Services) (plugin.Resources, error) {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return plugin.Resources{}, ctx.Err()
			}
			if services.Logger.Data["plugin_instance"] != spec.ID {
				return plugin.Resources{}, fmt.Errorf("wrong instance logger")
			}
			return plugin.Resources{Value: spec.ID}, nil
		},
		Configure: func(spec plugin.Spec) (plugin.Factory, error) {
			return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
				factories = append(factories, spec.ID)
				factoryContexts = append(factoryContexts, ctx)
				if services.Prepared != spec.ID {
					return nil, fmt.Errorf("resources out of order")
				}
				return new(interfaceSourcePlugin), nil
			}, nil
		},
	}
	specs := make([]plugin.Spec, 8)
	var want []string
	for i := range specs {
		specs[i] = plugin.Spec{ID: fmt.Sprint(i), Type: "fixture"}
		want = append(want, specs[i].ID)
	}
	configuration, err := Configure(map[string]plugin.Definition{"fixture": definition}, specs)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		instances, err := configuration.Prepare(ctx, plugin.Services{}, nil)
		for _, instance := range instances {
			err = errors.Join(err, instance.Release())
		}
		done <- err
	}()
	for range maxConcurrentResourceLoads {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("resource loads did not overlap")
		}
	}
	select {
	case <-started:
		t.Fatal("resource concurrency limit exceeded")
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !slices.Equal(factories, want) {
		t.Fatalf("factory order = %v", factories)
	}
	for _, factoryCtx := range factoryContexts {
		if factoryCtx.Err() != nil {
			t.Fatal("successful preparation canceled factory context")
		}
	}
}

func TestPrepareResourceFailureCancelsAndJoinsLoads(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{})
	exited := make(chan struct{})
	failure := errors.New("resource failure")
	configuration := &Configuration{instances: []configuredPlugin{
		{spec: plugin.Spec{ID: "waiting"}, resources: func(ctx context.Context, _ plugin.Spec, _ plugin.Services) (plugin.Resources, error) {
			close(entered)
			<-ctx.Done()
			close(exited)
			return plugin.Resources{}, ctx.Err()
		}},
		{spec: plugin.Spec{ID: "failure"}, resources: func(ctx context.Context, _ plugin.Spec, _ plugin.Services) (plugin.Resources, error) {
			select {
			case <-entered:
			case <-ctx.Done():
				return plugin.Resources{}, ctx.Err()
			}
			return plugin.Resources{}, failure
		}},
	}}
	instances, err := configuration.Prepare(ctx, plugin.Services{}, nil)
	if !errors.Is(err, failure) || len(instances) != 0 {
		t.Fatalf("Prepare = %v, %v", instances, err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("Prepare returned before canceled load exited")
	}
}

func TestPrepareFactoryFailureReleasesCandidateReferences(t *testing.T) {
	shared := new(interfaceSourcePlugin)
	existing := Adopt("shared", "fixture", shared)
	fresh := new(interfaceSourcePlugin)
	failure := errors.New("factory failed")
	configuration := &Configuration{instances: []configuredPlugin{
		{spec: plugin.Spec{ID: "shared", Type: "fixture"}},
		{spec: plugin.Spec{ID: "new"}, factory: func(context.Context, plugin.Services) (plugin.Plugin, error) { return fresh, nil }},
		{spec: plugin.Spec{ID: "failure"}, factory: func(context.Context, plugin.Services) (plugin.Plugin, error) { return nil, failure }},
	}}
	existing.input.config = configuration.instances[0].spec.Config
	instances, err := configuration.Prepare(t.Context(), plugin.Services{}, []*Instance{existing})
	if !errors.Is(err, failure) || len(instances) != 0 {
		t.Fatalf("Prepare = %v, %v", instances, err)
	}
	if shared.closed || !fresh.closed {
		t.Fatal("rollback released the wrong owners")
	}
	if err := existing.Release(); err != nil || !shared.closed {
		t.Fatal("candidate leaked shared reference")
	}
}
