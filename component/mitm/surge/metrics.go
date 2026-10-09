// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"time"

	"github.com/daeuniverse/dae/common/resource"

	"github.com/prometheus/client_golang/prometheus"
)

// All authority-scoped engine copies share these instance-owned collectors.
type engineMetrics struct {
	scripts  *prometheus.CounterVec
	duration *prometheus.HistogramVec
	wait     *prometheus.HistogramVec
	matches  *prometheus.CounterVec
	skips    *prometheus.CounterVec
	all      []prometheus.Collector
}

func newEngineMetrics(e *Engine) *engineMetrics {
	m := &engineMetrics{
		scripts:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "surge_scripts_total", Help: "Matched script invocations by phase and result, including skips before runtime execution and failures followed by transparent forwarding."}, []string{"phase", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "surge_script_duration_seconds", Help: "Runtime execution duration, excluding slot waits, body buffering and result application.", Buckets: prometheus.DefBuckets}, []string{"phase"}),
		wait:     prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "surge_execution_wait_duration_seconds", Help: "Execution slot acquisition duration, including canceled and timed out waits.", Buckets: prometheus.DefBuckets}, []string{"kind"}),
		matches:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "surge_rule_matches_total", Help: "HTTP rewrite, Map Local and DNS Host rule matches; a match need not result in a modification. DNS alias hops count separately."}, []string{"kind"}),
		skips:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "surge_processing_skips_total", Help: "Skipped script invocations or rewrite operations by bounded cause; body rewrite preparation failures count once per pass."}, []string{"stage", "reason"}),
	}
	modules := prometheus.NewGauge(prometheus.GaugeOpts{Name: "surge_modules", Help: "Loaded Surge modules."})
	modules.Set(float64(len(e.options.Modules)))
	rules := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "surge_rules", Help: "Loaded Surge rules by kind."}, []string{"kind"})
	for _, kind := range []string{"script", "url_rewrite", "header_rewrite", "body_rewrite", "map_local", "dns_host", "destination", "route"} {
		rules.WithLabelValues(kind)
	}
	for _, module := range e.options.Modules {
		for kind, count := range map[string]int{
			"script": len(module.Scripts) + len(module.TaskScripts), "url_rewrite": len(module.URLRewrites), "header_rewrite": len(module.HeaderRewrites),
			"body_rewrite": len(module.BodyRewrites), "map_local": len(module.MapLocals), "dns_host": len(module.DNSHosts),
			"destination": len(module.Hosts), "route": len(module.Rules),
		} {
			rules.WithLabelValues(kind).Add(float64(count))
		}
	}
	for _, phase := range []string{"http-request", "http-response", "dns", "cron", "generic"} {
		for _, result := range []string{"unchanged", "success", "synthetic", "abort", "failed", "skipped"} {
			m.scripts.WithLabelValues(phase, result)
		}
		m.duration.WithLabelValues(phase)
		m.wait.WithLabelValues(phase)
	}
	m.wait.WithLabelValues("body_rewrite")
	for _, kind := range []string{"url_rewrite", "header_rewrite", "body_rewrite", "map_local", "dns_host"} {
		m.matches.WithLabelValues(kind)
	}
	m.all = []prometheus.Collector{m.scripts, m.duration, m.wait, m.matches, m.skips, modules, rules,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "surge_execution_slots_in_use", Help: "Occupied execution slots, including body processing and DNS script continuations."}, func() float64 { return float64(len(e.slots)) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "surge_execution_slots_limit", Help: "Maximum concurrent execution slots shared by scripts and body rewrites."}, func() float64 { return float64(cap(e.slots)) }),
	}
	return m
}

func (m *engineMetrics) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range m.all {
		collector.Describe(ch)
	}
}

func (m *engineMetrics) Collect(ch chan<- prometheus.Metric) {
	for _, collector := range m.all {
		collector.Collect(ch)
	}
}

func (m *engineMetrics) match(kind string) {
	m.matches.WithLabelValues(kind).Inc()
}

func (m *engineMetrics) skip(stage, reason string) {
	m.skips.WithLabelValues(stage, reason).Inc()
}

func (e *Engine) runInvocation(ctx context.Context, script *Script, invocation Invocation) (*Result, error) {
	defer func(started time.Time) {
		e.metrics.duration.WithLabelValues(invocation.ScriptType).Observe(time.Since(started).Seconds())
	}(time.Now())
	source := script.Source
	if script.Debug {
		path := resource.Source{Location: script.Path}
		if !path.Remote() {
			result, err := resource.Read(ctx, nil, path, resource.ReadOptions{MaxBytes: MaxScriptBytes})
			if err != nil {
				return nil, err
			}
			source = string(result.Data)
		}
	}
	return e.options.Runtime.Run(ctx, source, invocation)
}
