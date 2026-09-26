// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

type endpointMetricsPlugin struct{ counter prometheus.Counter }

func (*endpointMetricsPlugin) Plan() plugin.Plan { return plugin.Plan{} }

func TestMetricsEndpointPublishesPluginLifecycle(t *testing.T) {
	startMetricsServer(0)
	t.Cleanup(func() { startMetricsServer(0) })
	t.Setenv("DAE_LOCATION_CACHE", t.TempDir())
	var current *endpointMetricsPlugin
	definitions := map[string]plugin.Definition{"fixture": {Configure: func(plugin.Spec) (plugin.Factory, error) {
		return func(_ context.Context, services plugin.Services) (plugin.Plugin, error) {
			current = &endpointMetricsPlugin{counter: prometheus.NewCounter(prometheus.CounterOpts{Name: "fixture_events_total", Help: "Endpoint fixture events."})}
			return current, services.Metrics.Register(current.counter)
		}, nil
	}}}
	load := func() *mitm.Host {
		host, err := loadTestMITM(t.Context(), mitmConfigForTest(t, "plugins { local { type: fixture } }"), nil, nil, definitions)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = host.Close() })
		return host
	}
	first := load()
	if err := first.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	current.counter.Add(5) // Collection is independent of listener state.
	port := freeLocalPort(t)
	startMetricsServer(port)
	_, _, server, _ := observabilityState()
	if server == nil {
		t.Fatal("metrics listener did not start")
	}
	scrape := func() string {
		response, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("scrape: %s %v", response.Status, err)
		}
		return string(body)
	}
	metric := `dae_plugin_fixture_events_total{plugin_instance="local",plugin_type="fixture"} `
	assert := func(want string) {
		t.Helper()
		body := scrape()
		if !strings.Contains(body, metric+want+"\n") || !strings.Contains(body, "dae_external_counter_read_errors_total") || !strings.Contains(body, "dae_plugin_instance_start_time_seconds") {
			t.Fatalf("missing combined metrics: %s", body)
		}
	}
	assert("5")
	second := load()
	assert("5")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	assert("0")
	_, _, afterReload, _ := observabilityState()
	if afterReload != server {
		t.Fatal("plugin reload restarted the listener")
	}
	startMetricsServer(0)
	current.counter.Add(3)
	startMetricsServer(port)
	assert("3")
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if body := scrape(); strings.Contains(body, "dae_plugin_") {
		t.Fatalf("closed instance remains exposed: %s", body)
	}
}
