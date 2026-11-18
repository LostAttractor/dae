// SPDX-License-Identifier: AGPL-3.0-only
package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
)

var metricsHandler = newRuntimeMetricsHandler(func() (control.RegistryUsage, bool) { return control.RegistryUsage{}, false })

func freeLocalPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	return port
}

func TestProfilingSwitchDoesNotDisableMetrics(t *testing.T) {
	ctx := context.WithValue(t.Context(), http.LocalAddrContextKey, &net.UnixAddr{Net: "unix", Name: "dae.sock"})
	for _, enabled := range []bool{true, false} {
		handler := apiserver.NewHandler(apiserver.Options{Pprof: enabled, Metrics: metricsHandler})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/debug/pprof/goroutine?debug=1", nil))
		want := http.StatusNotFound
		if enabled {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatal("profiling switch not applied", w.Code, w.Body.String())
		}
		if runtime.SetMutexProfileFraction(-1) != 0 {
			t.Fatal("profiling switch enabled continuous sampling")
		}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/metrics", nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "dae_process_") {
			t.Fatal("profiling changed metrics availability", w.Code, w.Body.String())
		}
	}
}

func TestMetricsServerContinuesAfterExternalCounterFailure(t *testing.T) {
	connection := stats.DefaultStore.OpenConnection(stats.Path{
		NodeID:   t.Name(),
		Outbound: t.Name(),
		Network:  common.NetworkTCP4,
	}, false)
	_ = connection.UpdateCounters(api.TrafficCounters{}, errors.New("counter source failed"))
	t.Cleanup(func() { _ = connection.Close() })

	response := httptest.NewRecorder()
	metricsHandler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "dae_external_counter_read_errors_total") {
		t.Fatalf("metrics response omitted external counter errors: %s", response.Body.String())
	}
}

func TestMetricsReportsCurrentDNSRegistryUsage(t *testing.T) {
	usage := control.RegistryUsage{UserUsed: 3, MemoryUsed: 300, MemoryLimit: 800, IncompleteBuckets: 1, OmittedPairs: 4}
	available := false
	handler := newRuntimeMetricsHandler(func() (control.RegistryUsage, bool) { return usage, available })
	scrape := func() string {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost/metrics", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("metrics status = %d, body = %s", response.Code, response.Body.String())
		}
		return response.Body.String()
	}
	if strings.Contains(scrape(), "dae_domain_registry_") {
		t.Fatal("unavailable registry had metric samples")
	}
	available = true
	body := scrape()
	for _, want := range []string{
		"dae_domain_registry_pairs 3\n",
		"dae_domain_registry_estimated_bytes 300\n",
		"dae_domain_registry_memory_limit_bytes 800\n",
		"dae_domain_registry_incomplete_buckets 1\n",
		"# TYPE dae_domain_registry_pair_omissions_total counter\n",
		"dae_domain_registry_pair_omissions_total 4\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics response omitted %q", want)
		}
	}
	usage.MemoryLimit = 1600
	usage.IncompleteBuckets = 0
	body = scrape()
	if !strings.Contains(body, "dae_domain_registry_memory_limit_bytes 1600\n") ||
		!strings.Contains(body, "dae_domain_registry_incomplete_buckets 0\n") ||
		!strings.Contains(body, "dae_domain_registry_pair_omissions_total 4\n") {
		t.Fatal("metrics did not use the current registry usage snapshot")
	}
}
