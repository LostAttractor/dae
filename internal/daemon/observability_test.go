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
	"github.com/daeuniverse/dae/internal/apiserver"
)

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
