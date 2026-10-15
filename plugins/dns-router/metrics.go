// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type routerMetrics struct {
	requests     *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	attempts     *prometheus.CounterVec
	attemptTime  *prometheus.HistogramVec
	decisions    *prometheus.CounterVec
	suppressions *prometheus.CounterVec
}

func newRouterMetrics() *routerMetrics {
	m := &routerMetrics{
		requests:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns_router_requests_total", Help: "Completed router invocations by entrypoint and result; success includes DNS error rcodes and policy rejections."}, []string{"entrypoint", "result"}),
		duration:     prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "dns_router_request_duration_seconds", Help: "Full router invocation duration including downstream middleware and auxiliary work.", Buckets: prometheus.DefBuckets}, []string{"entrypoint"}),
		attempts:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns_router_upstream_attempts_total", Help: "Transport exchange attempts, including address/transport fallback and canceled racing servers; bootstrap failures are excluded."}, []string{"upstream", "transport", "purpose", "result"}),
		attemptTime:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "dns_router_upstream_attempt_duration_seconds", Help: "Duration of each transport exchange attempt, excluding endpoint hostname bootstrap.", Buckets: prometheus.DefBuckets}, []string{"upstream", "transport", "purpose"}),
		decisions:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns_router_policy_decisions_total", Help: "Request and response policy decisions, separating main queries and family probes."}, []string{"stage", "action", "purpose"}),
		suppressions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns_router_family_suppressions_total", Help: "Answers suppressed because the preferred address family was available."}, []string{"family"}),
	}
	for _, entry := range []string{"middleware", "resolver"} {
		for _, result := range []string{"success", "bypass", "error", "timeout", "canceled"} {
			m.requests.WithLabelValues(entry, result)
		}
		m.duration.WithLabelValues(entry)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		m.suppressions.WithLabelValues(family)
	}
	return m
}

func (m *routerMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.requests, m.duration, m.attempts, m.attemptTime, m.decisions, m.suppressions}
}

func (m *routerMetrics) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range m.collectors() {
		collector.Describe(ch)
	}
}

func (m *routerMetrics) Collect(ch chan<- prometheus.Metric) {
	for _, collector := range m.collectors() {
		collector.Collect(ch)
	}
}

func metricResult(ctx context.Context, err error) string {
	if err == nil {
		return "success"
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
		return "timeout"
	}
	return "error"
}

func (m *routerMetrics) request(ctx context.Context, entry string, bypass bool, err error, started time.Time) {
	if m == nil {
		return
	}
	result := metricResult(ctx, err)
	if err == nil && bypass {
		result = "bypass"
	}
	m.requests.WithLabelValues(entry, result).Inc()
	m.duration.WithLabelValues(entry).Observe(time.Since(started).Seconds())
}

func (m *routerMetrics) decision(stage, action, purpose string) {
	if m != nil {
		m.decisions.WithLabelValues(stage, action, purpose).Inc()
	}
}

func (m *routerMetrics) attempt(ctx context.Context, upstream, transport, purpose string, err error, truncated bool, started time.Time) {
	if m == nil {
		return
	}
	result := metricResult(ctx, err)
	if err == nil && truncated {
		result = "truncated"
	}
	m.attempts.WithLabelValues(upstream, transport, purpose, result).Inc()
	m.attemptTime.WithLabelValues(upstream, transport, purpose).Observe(time.Since(started).Seconds())
}
