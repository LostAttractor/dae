// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	dns "github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func surgeMetric(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
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
			if matches {
				return metric
			}
		}
	}
	t.Fatalf("missing %s %v", name, labels)
	return nil
}

func surgeRegistry(t *testing.T, e *Engine) *prometheus.Registry {
	t.Helper()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(e.metrics); err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestScriptMetricsWithoutTraceAndSharedByConnections(t *testing.T) {
	for _, test := range []struct {
		name, source, result string
		forwards, aborts     bool
	}{
		{"noop", `$done({})`, "unchanged", true, false},
		{"rewrite", `$done({headers:{"X-Modified":"yes"}})`, "success", true, false},
		{"local", `$done({response:{status:201,body:"local"}})`, "synthetic", false, false},
		{"failed-forward", `throw Error("private URL or body")`, "failed", true, false},
		{"abort", `$done({abort:true})`, "abort", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := moduleScopeModule(t, "test", "a.test,b.test", "[Script]\nrun=type=http-request,pattern=.,script-path=run.js", map[string]string{"run": test.source})
			e := moduleScopeEngine(t, module)
			e.options.Logger = nil
			registry := surgeRegistry(t, e)
			for _, host := range []string{"a.test", "b.test"} {
				forwarded := false
				handler := e.Wrap(plugin.Flow{Host: host, Port: 80}, func(ex *plugin.Exchange) (*http.Response, error) {
					forwarded = true
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody, Request: ex.Request}, nil
				})
				request := httptest.NewRequest("GET", "http://"+host+"/", nil)
				response, err := handler(&plugin.Exchange{Request: request})
				if response != nil {
					_ = response.Body.Close()
				}
				if forwarded != test.forwards || errors.Is(err, plugin.ErrAbort) != test.aborts || err != nil && !test.aborts {
					t.Fatalf("forward=%t error=%v", forwarded, err)
				}
			}
			if got := surgeMetric(t, registry, "surge_scripts_total", map[string]string{"phase": "http-request", "result": test.result}).GetCounter().GetValue(); got != 2 {
				t.Fatalf("script count = %v", got)
			}
			if got := surgeMetric(t, registry, "surge_script_duration_seconds", map[string]string{"phase": "http-request"}).GetHistogram().GetSampleCount(); got != 2 {
				t.Fatalf("runtime observations = %v", got)
			}
			if got := surgeMetric(t, registry, "surge_execution_slots_in_use", nil).GetGauge().GetValue(); got != 0 {
				t.Fatalf("occupied slots = %v", got)
			}
		})
	}
}

func TestScriptMetricsDistinguishSkippedFromExecuted(t *testing.T) {
	for _, phase := range []string{"http-request", "http-response"} {
		t.Run(phase, func(t *testing.T) {
			module := moduleScopeModule(t, "test", "a.test", "[Script]\nrun=type="+phase+",pattern=.,requires-body=1,max-size=16,script-path=run.js", map[string]string{"run": `$done({body:"modified"})`})
			e := moduleScopeEngine(t, module)
			e.options.Logger = nil
			registry := surgeRegistry(t, e)
			reason := "body_limit"
			if phase == "http-request" {
				e.options.BodyMemory = membuffer.NewBudget(1)
				reason = "buffer_memory_limit"
				request := httptest.NewRequest("POST", "http://a.test/", strings.NewReader("original"))
				defer func() { _ = request.Body.Close() }()
				if _, err := e.processRequest(&plugin.Exchange{Request: request}); err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(request.Body)
				if err != nil || string(body) != "original" {
					t.Fatalf("fallback body=%q error=%v", body, err)
				}
			} else {
				response := bodyRewriteResponse([]byte(strings.Repeat("x", 32)), "")
				defer func() { _ = response.Body.Close() }()
				if err := e.processResponse(response, nil); err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				if err != nil || len(body) != 32 {
					t.Fatalf("response truncated: %d %v", len(body), err)
				}
			}
			if got := surgeMetric(t, registry, "surge_scripts_total", map[string]string{"phase": phase, "result": "skipped"}).GetCounter().GetValue(); got != 1 {
				t.Fatalf("skips=%v", got)
			}
			if got := surgeMetric(t, registry, "surge_processing_skips_total", map[string]string{"stage": phase, "reason": reason}).GetCounter().GetValue(); got != 1 {
				t.Fatalf("skip causes=%v", got)
			}
			if got := surgeMetric(t, registry, "surge_script_duration_seconds", map[string]string{"phase": phase}).GetHistogram().GetSampleCount(); got != 0 {
				t.Fatalf("skipped script recorded runtime=%v", got)
			}
		})
	}
}

func TestBodyRewriteDecodeFailureMetrics(t *testing.T) {
	for _, test := range []struct {
		name, encoding, reason string
		bodyLimit              int64
		exhaustBudget          bool
		malformed              bool
	}{
		{name: "gzip size limit", encoding: "gzip", reason: "body_limit", bodyLimit: 128},
		{name: "brotli size limit", encoding: "br", reason: "body_limit", bodyLimit: 128},
		{name: "gzip memory limit", encoding: "gzip", reason: "buffer_memory_limit", bodyLimit: 2048, exhaustBudget: true},
		{name: "brotli memory limit", encoding: "br", reason: "buffer_memory_limit", bodyLimit: 2048, exhaustBudget: true},
		{name: "invalid gzip", encoding: "gzip", reason: "decode_failed", bodyLimit: 2048, malformed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := moduleScopeModule(t, "rewrite", "example.test", "[Body Rewrite]\nhttp-response-jq . '.x=1'", nil)
			e := moduleScopeEngine(t, module)
			budget := membuffer.NewBudget(1 << 20)
			e.options.BodyMemory, e.options.MaxBodySize = budget, test.bodyLimit
			var capture proxyTraceCapture
			e.options.Logger = capture.logger()
			registry := surgeRegistry(t, e)
			raw := encodeBodyRewriteTest(t, []byte(`{"x":"`+strings.Repeat("a", 1000)+`"}`), test.encoding)
			if test.malformed {
				raw = []byte("invalid gzip")
			}
			response := bodyRewriteResponse(raw, test.encoding)
			defer func() { _ = response.Body.Close() }()
			// Complete the compressed snapshot first, so limits are encountered
			// during decoding rather than while buffering the original response.
			snapshot, err := plugin.SnapshotBody(&response.Body, test.bodyLimit, budget)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.Close()
			if test.exhaustBudget {
				limit := budget.UseLimit(budget.Status().Used)
				defer limit.Close()
			}
			if err := e.rewriteResponseBody(response); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || !bytes.Equal(body, raw) || response.Header.Get("Content-Encoding") != test.encoding || response.ContentLength != int64(len(raw)) {
				t.Fatalf("decode fallback changed the response: body=%q error=%v", body, err)
			}
			if status := budget.Status(); status.Used != 0 || (status.Denied != 0) != test.exhaustBudget {
				t.Fatalf("unexpected decode memory accounting: %+v", status)
			}
			if got := surgeMetric(t, registry, "surge_processing_skips_total", map[string]string{"stage": "body_rewrite", "reason": test.reason}).GetCounter().GetValue(); got != 1 {
				t.Fatalf("decode skips=%v", got)
			}
			findProxyTraceEvent(t, capture.trace, "body_rewrite_skip", map[string]string{"reason": test.reason})
		})
	}
}

func TestDNSScriptMetricsExcludeDownstreamFailures(t *testing.T) {
	for _, test := range []struct {
		source, result    string
		downstream, fails bool
	}{
		{`$done({address:"192.0.2.1"})`, "synthetic", false, false},
		{`throw Error("script failure")`, "failed", false, true},
		{`$done({address:"invalid"})`, "failed", false, true},
		{`$done({})`, "unchanged", true, true},
		{`$done({server:"192.0.2.54"})`, "success", true, true},
	} {
		t.Run(test.source, func(t *testing.T) {
			module := moduleScopeModule(t, "dns", "", "[Host]\nscript.test=script:answer\n[Script]\nanswer=type=dns,script-path=answer.js", map[string]string{"answer": test.source})
			e := moduleScopeEngine(t, module)
			e.options.Logger = nil
			registry := surgeRegistry(t, e)
			called := false
			_, err := e.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				called = true
				return nil, errors.New("downstream failure")
			})(t.Context(), hostDNSRequest(t, "script.test.", dns.TypeA))
			if called != test.downstream || (err != nil) != test.fails {
				t.Fatalf("downstream=%t error=%v", called, err)
			}
			if got := surgeMetric(t, registry, "surge_scripts_total", map[string]string{"phase": "dns", "result": test.result}).GetCounter().GetValue(); got != 1 {
				t.Fatalf("DNS outcome count=%v", got)
			}
			if got := surgeMetric(t, registry, "surge_script_duration_seconds", map[string]string{"phase": "dns"}).GetHistogram().GetSampleCount(); got != 1 {
				t.Fatalf("DNS runtime count=%v", got)
			}
		})
	}
}

func TestSurgeRuleMetricsConcurrentScopes(t *testing.T) {
	module := moduleScopeModule(t, "headers", "a.test,b.test", "[Header Rewrite]\nhttp-request . header-add X-Test yes", nil)
	e := moduleScopeEngine(t, module)
	e.options.Logger = nil
	registry := surgeRegistry(t, e)
	var wg sync.WaitGroup
	for _, host := range []string{"a.test", "b.test"} {
		wg.Go(func() {
			handler := e.Wrap(plugin.Flow{Host: host, Port: 80}, func(ex *plugin.Exchange) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody, Request: ex.Request}, nil
			})
			for range 50 {
				request := httptest.NewRequest("GET", "http://"+host+"/", nil)
				response, err := handler(&plugin.Exchange{Request: request})
				if err != nil {
					t.Error(err)
					return
				}
				_ = response.Body.Close()
				if request.Header.Get("X-Test") != "yes" {
					t.Error("rule did not execute")
				}
				if _, err := registry.Gather(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if got := surgeMetric(t, registry, "surge_rule_matches_total", map[string]string{"kind": "header_rewrite"}).GetCounter().GetValue(); got != 100 {
		t.Fatalf("matches=%v", got)
	}
	if got := surgeMetric(t, registry, "surge_rules", map[string]string{"kind": "header_rewrite"}).GetGauge().GetValue(); got != 1 {
		t.Fatalf("configured rules=%v", got)
	}
}
