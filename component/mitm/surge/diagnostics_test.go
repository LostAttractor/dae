// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
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
	engine := &Engine{options: EngineOptions{Modules: []*Module{module}}}
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
	// No runtime, metrics, transport or script source exists in this fixture.
	engine := &Engine{options: EngineOptions{Modules: []*Module{module}}}
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
