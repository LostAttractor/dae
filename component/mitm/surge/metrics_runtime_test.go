// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"strings"
	"testing"
	"time"
)

func TestRuntimeMetricsAndStatus(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{Timeout: time.Second, NodeWorkers: 2})
	e := newTestEngine(t, EngineOptions{Runtime: r.Runtime})
	registry := surgeRegistry(t, e)
	if got := surgeMetric(t, registry, "surge_runtime_info", map[string]string{"backend": compiledJSRuntime}).GetGauge().GetValue(); got != 1 {
		t.Fatalf("runtime info = %v", got)
	}
	if got := e.Status().Runtimes; len(got) != 1 || got[0].Backend != compiledJSRuntime {
		t.Fatalf("runtime status = %+v", got)
	}
	if compiledJSRuntime != "nodejs" {
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if strings.HasPrefix(family.GetName(), "surge_nodejs_") {
				t.Fatalf("QuickJS exported Node.js metrics: %s", family.GetName())
			}
		}
		return
	}
	if n := e.Status().Runtimes[0].NodeJS; n.Started != 0 || n.Idle != 0 || n.Active != 0 {
		t.Fatalf("startup probe included in application counters: %+v", n)
	}
	for range 2 {
		if _, err := r.Run(t.Context(), `$done({})`, Invocation{}); err != nil {
			t.Fatal(err)
		}
	}
	n := e.Status().Runtimes[0].NodeJS
	if n.Started != 1 || n.Reused != 1 || n.Active != 0 || n.Idle != 1 || n.Limit != 2 {
		t.Fatalf("reuse status = %+v", n)
	}
	for name, want := range map[string]float64{
		"surge_nodejs_worker_starts_total":         float64(n.Started),
		"surge_nodejs_worker_reuses_total":         float64(n.Reused),
		"surge_nodejs_worker_start_failures_total": 0,
	} {
		if got := surgeMetric(t, registry, name, nil).GetCounter().GetValue(); got != want {
			t.Errorf("%s = %v, status = %v", name, got, want)
		}
	}
	if got := surgeMetric(t, registry, "surge_nodejs_workers", map[string]string{"state": "idle"}).GetGauge().GetValue(); got != float64(n.Idle) {
		t.Fatalf("idle gauge = %v, status=%+v", got, n)
	}
	if _, err := r.Run(t.Context(), `throw Error("fixture")`, Invocation{}); err == nil {
		t.Fatal("expected script failure")
	}
	if got := surgeMetric(t, registry, "surge_nodejs_worker_retirements_total", map[string]string{"reason": "failed"}).GetCounter().GetValue(); got != 1 || e.Status().Runtimes[0].NodeJS.Discarded != 1 {
		t.Fatalf("failed retirement = %v, status=%+v", got, e.Status().Runtimes)
	}
}
