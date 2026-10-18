// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/prometheus/client_golang/prometheus"
)

type reloadPlugin struct {
	metricsTestPlugin
	runs    atomic.Int32
	started chan struct{}
	stopped chan struct{}
	ctx     context.Context
}

func (p *reloadPlugin) Run(ctx context.Context, _ *http.Client) error {
	p.ctx = ctx
	p.runs.Add(1)
	close(p.started)
	<-ctx.Done()
	close(p.stopped)
	return nil
}

func TestReloadReusesInstancesWorkersAndMetrics(t *testing.T) {
	var metrics Metrics
	versions := map[string]string{"one": "1", "two": "1"}
	var constructed []*reloadPlugin
	var refreshes atomic.Int32
	definition := testDefinition(func(_ context.Context, _ plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
		p := &reloadPlugin{started: make(chan struct{}), stopped: make(chan struct{})}
		p.counter = prometheus.NewCounter(prometheus.CounterOpts{Name: "fixture_events_total", Help: "Fixture events."})
		constructed = append(constructed, p)
		return p, services.Metrics.Register(p.counter)
	})
	definition.Resources = func(_ context.Context, spec plugin.Spec, _ plugin.Services) (plugin.Resources, error) {
		refreshes.Add(1)
		if versions[spec.ID] == "error" {
			return plugin.Resources{}, errors.New("refresh failed")
		}
		return plugin.Resources{Key: versions[spec.ID]}, nil
	}
	load := func(previous *Host, wantError bool) *Host {
		t.Helper()
		configuration, err := pluginhost.Configure(map[string]plugin.Definition{"fixture": definition}, []plugin.Spec{{ID: "one", Type: "fixture"}, {ID: "two", Type: "fixture"}})
		if err != nil {
			t.Fatal(err)
		}
		host, err := Load(t.Context(), configuration, Options{Metrics: &metrics}, plugin.Services{}, previous)
		if (err != nil) != wantError {
			t.Fatalf("load error = %v", err)
		}
		if host != nil {
			t.Cleanup(func() { _ = host.Close() })
		}
		return host
	}
	first := load(nil, false)
	if err := first.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, p := range constructed {
		<-p.started
		p.counter.Add(7)
	}
	abandoned := load(first, false)
	if !first.SameRuntime(abandoned) || len(constructed) != 2 || refreshes.Load() != 4 {
		t.Fatal("unchanged resource refresh reconstructed instances")
	}
	if err := abandoned.Close(); err != nil {
		t.Fatal(err)
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 7, "two": 7})
	versions["one"] = "2"
	versions["two"] = "error"
	load(first, true)
	if len(constructed) != 2 || constructed[0].closed.Load() || constructed[1].closed.Load() {
		t.Fatal("failed resource preparation constructed candidates or released live instances")
	}
	versions["two"] = "1"
	next := load(first, false)
	if first.instances[0].owner == next.instances[0].owner || first.instances[1].owner != next.instances[1].owner {
		t.Fatal("replacement did not follow instance changes")
	}
	if err := next.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-constructed[2].started
	first.StopWorkers()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	<-constructed[0].stopped
	if constructed[1].runs.Load() != 1 || constructed[1].closed.Load() {
		t.Fatal("retiring a host stopped a shared worker")
	}
	if err := constructed[1].ctx.Err(); err != nil {
		t.Fatalf("shared worker lost its active owner: %v", err)
	}
	select {
	case <-constructed[1].stopped:
		t.Fatal("shared worker canceled")
	default:
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 0, "two": 7})
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2} {
		<-constructed[index].stopped
		if !constructed[index].closed.Load() {
			t.Fatal("final host leaked an instance")
		}
	}
}
