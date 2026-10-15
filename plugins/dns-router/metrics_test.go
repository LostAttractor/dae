// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dns "github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

func metricRouter(t *testing.T, config string) (*Router, *prometheus.Registry) {
	t.Helper()
	sections, err := config_parser.Parse("router {" + config + "}")
	if err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewPedanticRegistry()
	factory, err := Configure(plugin.Spec{Config: sections[0]})
	if err != nil {
		t.Fatal(err)
	}
	p, err := factory(t.Context(), plugin.Services{BaseDir: t.TempDir(), Metrics: registry})
	if err != nil {
		t.Fatal(err)
	}
	r := p.(*Router)
	t.Cleanup(func() { _ = r.Close() })
	return r, registry
}

// Histograms return sample count so tests verify operation boundaries without
// relying on wall-clock timing.
func routerMetric(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			matches := len(metric.Label) == len(labels)
			for _, label := range metric.Label {
				matches = matches && labels[label.GetName()] == label.GetValue()
			}
			if !matches {
				continue
			}
			if metric.Histogram != nil {
				return float64(metric.GetHistogram().GetSampleCount())
			}
			return metric.GetCounter().GetValue()
		}
	}
	t.Fatalf("missing metric %s %v", name, labels)
	return 0
}

func TestRouterMetricsSeparateFallbackAttempts(t *testing.T) {
	address := exchangeServer(t, "tcp", func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetReply(q) })
	r, registry := metricRouter(t, fmt.Sprintf("upstream { primary: 'tcp+udp://%s' } routing { request { fallback: primary } }", address))
	request := safetyRequest(dns.TypeA)
	request.DialContext = func(ctx context.Context, network, target, _ string) (net.Conn, error) {
		if network == "udp" {
			return nil, context.DeadlineExceeded
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	response, err := r.WrapDNS(nil)(t.Context(), request)
	if err != nil || response == nil {
		t.Fatalf("fallback failed: %v", err)
	}
	if got := routerMetric(t, registry, "dns_router_requests_total", map[string]string{"entrypoint": "middleware", "result": "success"}); got != 1 {
		t.Fatalf("requests=%v", got)
	}
	if got := routerMetric(t, registry, "dns_router_request_duration_seconds", map[string]string{"entrypoint": "middleware"}); got != 1 {
		t.Fatalf("request timings=%v", got)
	}
	for transport, result := range map[string]string{"udp": "timeout", "tcp": "success"} {
		labels := map[string]string{"upstream": "primary", "transport": transport, "purpose": "query", "result": result}
		if got := routerMetric(t, registry, "dns_router_upstream_attempts_total", labels); got != 1 {
			t.Fatalf("%s attempts=%v", transport, got)
		}
		delete(labels, "result")
		if got := routerMetric(t, registry, "dns_router_upstream_attempt_duration_seconds", labels); got != 1 {
			t.Fatalf("%s timings=%v", transport, got)
		}
	}
}

func TestRouterMetricsSeparateFamilyProbesAndReroutes(t *testing.T) {
	answer := func(q *dns.Msg) *dns.Msg {
		response := new(dns.Msg).SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		}
		return response
	}
	first := exchangeServer(t, "udp", answer)
	second := exchangeServer(t, "udp", answer)
	r, registry := metricRouter(t, fmt.Sprintf(`ipversion_prefer: 4
upstream { first: 'udp://%s' second: 'udp://%s' }
routing { request { fallback: first } response { upstream(first) -> second fallback: accept } }`, first, second))
	request := safetyRequest(dns.TypeAAAA)
	request.DialContext = func(ctx context.Context, network, target, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	response, err := r.WrapDNS(nil)(t.Context(), request)
	if err != nil || response == nil || len(response.MessageCopy().Answer) != 0 {
		t.Fatalf("family resolution failed: %v %v", response, err)
	}
	if got := routerMetric(t, registry, "dns_router_requests_total", map[string]string{"entrypoint": "middleware", "result": "success"}); got != 1 {
		t.Fatalf("probes counted as client requests: %v", got)
	}
	for _, purpose := range []string{"query", "probe"} {
		for _, upstream := range []string{"first", "second"} {
			if got := routerMetric(t, registry, "dns_router_upstream_attempts_total", map[string]string{"upstream": upstream, "transport": "udp", "purpose": purpose, "result": "success"}); got != 1 {
				t.Fatalf("%s %s attempts=%v", upstream, purpose, got)
			}
		}
		if got := routerMetric(t, registry, "dns_router_policy_decisions_total", map[string]string{"stage": "response", "action": "reroute", "purpose": purpose}); got != 1 {
			t.Fatalf("reroutes=%v", got)
		}
	}
	if got := routerMetric(t, registry, "dns_router_family_suppressions_total", map[string]string{"family": "ipv6"}); got != 1 {
		t.Fatalf("suppressions=%v", got)
	}
}

func TestRouterMetricsExplicitRaceCancellation(t *testing.T) {
	address := exchangeServer(t, "udp", func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetReply(q) })
	r, registry := metricRouter(t, "")
	request := safetyRequest(dns.TypeA)
	loserStarted := make(chan struct{})
	request.DialContext = func(ctx context.Context, network, target, _ string) (net.Conn, error) {
		if target == "192.0.2.53:53" {
			close(loserStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		select {
		case <-loserStarted:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address.String())
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := r.ResolveDNS(ctx, request, []string{"192.0.2.53", "192.0.2.54"}); err != nil {
		t.Fatal(err)
	}
	for _, result := range []string{"success", "canceled"} {
		if got := routerMetric(t, registry, "dns_router_upstream_attempts_total", map[string]string{"upstream": "explicit", "transport": "udp", "purpose": "explicit", "result": result}); got != 1 {
			t.Fatalf("%s attempts=%v", result, got)
		}
	}
	if got := routerMetric(t, registry, "dns_router_requests_total", map[string]string{"entrypoint": "resolver", "result": "success"}); got != 1 {
		t.Fatalf("resolver requests=%v", got)
	}
}

func TestRouterMetricsBypassErrorsAndPolicyRejection(t *testing.T) {
	r, registry := metricRouter(t, "")
	request := safetyRequest(dns.TypeA)
	for _, cause := range []error{errors.New("private upstream error"), context.DeadlineExceeded, context.Canceled} {
		_, err := r.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return nil, cause })(t.Context(), request)
		if !errors.Is(err, cause) {
			t.Fatalf("lost error: %v", err)
		}
	}
	invalid := request.Copy()
	invalid.DNSPacket = plugin.DNSPacket{}
	assigned := request.Copy()
	assigned.ServerAssigned = true
	for _, bypass := range []*plugin.DNSExchange{invalid, assigned} {
		_, err := r.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return nil, nil })(t.Context(), bypass)
		if err != nil {
			t.Fatal(err)
		}
	}
	for result, want := range map[string]float64{"error": 1, "timeout": 1, "canceled": 1, "bypass": 2} {
		if got := routerMetric(t, registry, "dns_router_requests_total", map[string]string{"entrypoint": "middleware", "result": result}); got != want {
			t.Fatalf("%s requests=%v", result, got)
		}
	}
	reject, rejectRegistry := metricRouter(t, "routing { request { fallback: reject } }")
	response, err := reject.WrapDNS(nil)(t.Context(), request)
	if err != nil || response == nil {
		t.Fatalf("reject failed: %v", err)
	}
	if got := routerMetric(t, rejectRegistry, "dns_router_policy_decisions_total", map[string]string{"stage": "request", "action": "reject", "purpose": "query"}); got != 1 {
		t.Fatalf("rejections=%v", got)
	}
	if got := routerMetric(t, rejectRegistry, "dns_router_requests_total", map[string]string{"entrypoint": "middleware", "result": "success"}); got != 1 {
		t.Fatalf("policy rejection classified as failure: %v", got)
	}
}
