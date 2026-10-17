// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"context"
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func TestExplainScriptSNIKeepsDestinationPort(t *testing.T) {
	module, err := Parse(`[MITM]
hostname = script.test:8443
[Script]
rewrite = type=http-request,pattern=^https://script\.test:8443/path,script-path=rewrite.js
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := diagnosticTestEngine(module)
	request := httptest.NewRequest(http.MethodGet, "https://192.0.2.1:8443/path", nil)
	request.TLS = &tls.ConnectionState{ServerName: "script.test"}
	if _, script := engine.matchScript("http-request", request); script == nil {
		t.Fatal("runtime did not select the script via SNI")
	}
	result := engine.Explain(t.Context(), api.ExplainRequest{Flow: api.DiagnosticFlow{
		Destination: api.DiagnosticTarget{Port: 8443}, SNI: new("script.test"),
		HTTP: &api.DiagnosticHTTP{URL: request.URL.String(), Host: request.Host},
	}})
	for _, step := range result.Steps {
		if step.Reason == "script_execution_required" {
			return
		}
	}
	t.Fatalf("explanation disagreed with runtime matching: %+v", result.Steps)
}

func TestExplainDNSQuestionApplicabilityMatchesRuntime(t *testing.T) {
	module, err := Parse("[Host]\nexample.test = 192.0.2.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(t, EngineOptions{Modules: []*Module{module}})
	for _, class := range []uint16{dns.ClassINET, dns.ClassCHAOS} {
		for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeAXFR, dns.TypeIXFR, dns.TypeTKEY} {
			query := new(dns.Msg).SetQuestion("example.test.", kind)
			query.Question[0].Qclass = class
			forwarded := false
			_, err := engine.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				forwarded = true
				return nil, nil
			})(t.Context(), &plugin.DNSExchange{DNSRequest: plugin.DNSRequest{DNSPacket: plugin.DNSMessage(query)}})
			if err != nil {
				t.Fatal(err)
			}
			ctx := plugin.WithDiagnosticDNSRequest(t.Context(), plugin.DNSRequest{DNSPacket: plugin.DNSMessage(query)})
			result := engine.Explain(ctx, api.ExplainRequest{Kind: "dns", DNS: &api.DiagnosticDNS{Name: "example.test.", Type: dns.TypeToString[kind], Class: dns.ClassToString[class]}})
			if result.Terminal == forwarded || !result.Complete {
				t.Fatalf("class=%d type=%d runtime forwarded=%v explanation=%+v", class, kind, forwarded, result)
			}
		}
	}
}

func TestExplainDeclarativeRewriteAndDynamicBoundary(t *testing.T) {
	module, err := Parse(`[MITM]
hostname = example.com
[URL Rewrite]
^https://example.com/local - reject
^https://example.com/old https://example.com/new header
[Script]
first = type=http-request, pattern=^https://example.com/new, script-path=first.js
second = type=http-request, pattern=^https://example.com/new, script-path=second.js
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	// No runtime, transport or script source exists in this fixture.
	engine := diagnosticTestEngine(module)
	request := api.ExplainRequest{Flow: api.DiagnosticFlow{Destination: api.DiagnosticTarget{Port: 443}, HTTP: &api.DiagnosticHTTP{URL: "https://example.com/old", Headers: map[string][]string{"X-Original": {"kept"}}}}}
	before := map[string][]string{"X-Original": {"kept"}}
	result := engine.Explain(t.Context(), request)
	if result.Complete || result.Terminal || result.HTTP.URL != "https://example.com/new" {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(before, request.Flow.HTTP.Headers) || request.Flow.HTTP.URL != "https://example.com/old" {
		t.Fatal("explanation mutated input")
	}
	dynamic, skipped := false, false
	for _, step := range result.Steps {
		dynamic = dynamic || step.Reason == "script_execution_required"
		skipped = skipped || step.Reason == "earlier_script"
	}
	if !dynamic || !skipped {
		t.Fatal("script order or unknown boundary lost", result.Steps)
	}
	request.Flow.HTTP.URL = "https://example.com/local"
	result = engine.Explain(t.Context(), request)
	if !result.Complete || !result.Terminal {
		t.Fatal(result)
	}
	for _, step := range result.Steps {
		if strings.Contains(step.Expression, "first:") && step.Status != "not_reached" {
			t.Fatal("local response executed a script", step)
		}
	}
}

func diagnosticTestEngine(module *Module) *Engine {
	e := &Engine{options: EngineOptions{Modules: []*Module{module}, ScriptTimeout: DefaultScriptTimeout}, slots: make(chan struct{}, 1)}
	e.metrics = newEngineMetrics(e)
	return e
}

func TestExplainURLRuleOrderMatchesRuntimeAcrossModules(t *testing.T) {
	for _, action := range []string{"header", "302", "reject"} {
		replacement := "https://example.com/changed"
		if action == "reject" {
			replacement = "-"
		}
		first, err := Parse("[MITM]\nhostname = example.com\n[URL Rewrite]\n^https://example.com/start "+replacement+" "+action, nil)
		if err != nil {
			t.Fatal(err)
		}
		second, err := Parse("[MITM]\nhostname = example.com\n[URL Rewrite]\n^https://example.com/ - reject", nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := newTestEngine(t, EngineOptions{Modules: []*Module{first, second}})
		request := httptest.NewRequest(http.MethodGet, "https://example.com/start", nil)
		response, err := engine.rewriteURL(request)
		if err != nil {
			t.Fatal(err)
		}
		result := engine.Explain(t.Context(), api.ExplainRequest{Flow: api.DiagnosticFlow{Destination: api.DiagnosticTarget{Port: 443}, HTTP: &api.DiagnosticHTTP{URL: "https://example.com/start"}}})
		if !result.Complete || result.Terminal != (response != nil) || result.HTTP.URL != request.URL.String() {
			t.Fatalf("action=%s runtime URL=%s response=%v explanation=%+v", action, request.URL, response, result)
		}
	}
}

func TestExplainDNSAliasPreservesRuntimeQuery(t *testing.T) {
	module, err := Parse("[Host]\noriginal.test = alias.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(t, EngineOptions{Modules: []*Module{module}})
	query := new(dns.Msg).SetQuestion("original.test.", dns.TypeAAAA)
	query.RecursionDesired, query.CheckingDisabled = false, true
	query.SetEdns0(1232, true)
	query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}}}
	request := plugin.DNSRequest{DNSPacket: plugin.DNSMessage(query)}
	var forwarded *dns.Msg
	_, err = engine.WrapDNS(func(_ context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		forwarded = request.MessageCopy()
		return nil, nil
	})(t.Context(), &plugin.DNSExchange{DNSRequest: request})
	if err != nil {
		t.Fatal(err)
	}
	ctx := plugin.WithDiagnosticDNSRequest(t.Context(), request)
	result := engine.Explain(ctx, api.ExplainRequest{Kind: "dns", DNS: &api.DiagnosticDNS{Name: "stale.test.", Type: "A", Class: "CH"}})
	if !result.Complete || result.Terminal || !reflect.DeepEqual(result.DNS, forwarded) {
		t.Fatalf("diagnostic query=%s runtime=%s", result.DNS, forwarded)
	}
}
