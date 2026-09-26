// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

type metricsTestPlugin struct {
	counter prometheus.Counter
	closed  atomic.Bool
}

func (*metricsTestPlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *metricsTestPlugin) Close() error    { p.closed.Store(true); return nil }

func assertPluginCounters(t *testing.T, metrics *Metrics, want map[string]float64) {
	t.Helper()
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]float64)
	for _, family := range families {
		if family.GetName() != "dae_plugin_fixture_events_total" {
			continue
		}
		for _, metric := range family.Metric {
			var id, typ string
			for _, label := range metric.Label {
				switch label.GetName() {
				case "plugin_instance":
					id = label.GetValue()
				case "plugin_type":
					typ = label.GetValue()
				}
			}
			if typ != "fixture" || id == "" {
				t.Fatalf("missing host labels: %v", metric)
			}
			got[id] = metric.GetCounter().GetValue()
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("counters = %v, want %v", got, want)
	}
}

func TestPluginMetricsPreparationReloadAndRemoval(t *testing.T) {
	var metrics Metrics
	var prepared []*metricsTestPlugin
	definitions := map[string]plugin.Definition{"fixture": testDefinition(func(_ context.Context, spec plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
		counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "fixture_events_total", Help: "Fixture events."})
		if err := services.Metrics.Register(counter); err != nil {
			return nil, err
		}
		if spec.ID == "fail" {
			return nil, errors.New("failed after registering metrics")
		}
		p := &metricsTestPlugin{counter: counter}
		prepared = append(prepared, p)
		return p, nil
	})}
	load := func(ids ...string) (*Host, error) {
		var specs []plugin.Spec
		for _, id := range ids {
			specs = append(specs, plugin.Spec{ID: id, Type: "fixture"})
		}
		return loadTestPlugins(t.Context(), definitions, specs, Options{Metrics: &metrics}, plugin.Services{})
	}
	first, err := load("one", "removed")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	assertPluginCounters(t, &metrics, map[string]float64{})
	if err := first.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	prepared[0].counter.Add(7)
	prepared[1].counter.Inc()
	assertPluginCounters(t, &metrics, map[string]float64{"one": 7, "removed": 1})

	if _, err := load("one", "fail"); err == nil {
		t.Fatal("failed preparation accepted")
	}
	if !prepared[2].closed.Load() {
		t.Fatal("failed preparation leaked earlier plugin")
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 7, "removed": 1})

	abandoned, err := load("one")
	if err != nil {
		t.Fatal(err)
	}
	if err := abandoned.Close(); err != nil {
		t.Fatal(err)
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 7, "removed": 1})

	second, err := load("one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	assertPluginCounters(t, &metrics, map[string]float64{"one": 7, "removed": 1})
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 0})
	prepared[len(prepared)-1].counter.Inc()
	if err := second.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 1})
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	families, err := metrics.Gather()
	if err != nil || len(families) != 0 {
		t.Fatalf("retired series remain: %v %v", families, err)
	}
}

func TestPluginMetricDefinitionConflictRollsBack(t *testing.T) {
	var first *metricsTestPlugin
	definitions := map[string]plugin.Definition{"fixture": testDefinition(func(_ context.Context, spec plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
		p := &metricsTestPlugin{counter: prometheus.NewCounter(prometheus.CounterOpts{Name: "fixture_events_total", Help: spec.ID})}
		if err := services.Metrics.Register(p.counter); err != nil {
			return nil, err
		}
		first = p
		return p, nil
	})}
	host, err := loadTestPlugins(t.Context(), definitions, []plugin.Spec{{ID: "one", Type: "fixture"}, {ID: "different-help", Type: "fixture"}}, Options{}, plugin.Services{})
	if err == nil || host != nil || first == nil || !first.closed.Load() {
		t.Fatalf("conflicting definitions were not rolled back: %v", err)
	}
}

type blockingMetricsPlugin struct {
	metricsTestPlugin
	started, release chan struct{}
	desc             *prometheus.Desc
}

func (p *blockingMetricsPlugin) Describe(ch chan<- *prometheus.Desc) { ch <- p.desc }
func (p *blockingMetricsPlugin) Collect(ch chan<- prometheus.Metric) {
	close(p.started)
	<-p.release
	ch <- prometheus.MustNewConstMetric(p.desc, prometheus.GaugeValue, 1)
}

func TestPluginCloseJoinsInflightScrape(t *testing.T) {
	var metrics Metrics
	p := &blockingMetricsPlugin{started: make(chan struct{}), release: make(chan struct{}), desc: prometheus.NewDesc("fixture_blocking", "Blocking collector.", nil, nil)}
	host, err := loadTestPlugins(t.Context(), map[string]plugin.Definition{"fixture": testDefinition(func(_ context.Context, _ plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
		return p, services.Metrics.Register(p)
	})}, []plugin.Spec{{ID: "one", Type: "fixture"}}, Options{Metrics: &metrics}, plugin.Services{})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	gathered := make(chan error, 1)
	go func() { _, err := metrics.Gather(); gathered <- err }()
	<-p.started
	closed := make(chan error, 1)
	go func() { closed <- host.Close() }()
	// RWMutex waits are not durably blocked operations for testing/synctest.
	select {
	case err := <-closed:
		close(p.release)
		t.Fatalf("Close returned during collection: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if p.closed.Load() {
		t.Error("plugin resources closed during collection")
	}
	close(p.release)
	if err := <-gathered; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if !p.closed.Load() {
		t.Fatal("plugin was not closed")
	}
	families, err := metrics.Gather()
	if err != nil || len(families) != 0 {
		t.Fatalf("closed plugin remains published: %v %v", families, err)
	}
}
