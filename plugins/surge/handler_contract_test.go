// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestScriptMatchesHostAndSNIAfterScopeAdmission(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
first=type=http-request,pattern=^https://sni.example:8443/path,script-path=a.js
second=type=http-request,pattern=^https://host.example:8443/path,script-path=a.js
third=type=http-request,pattern=^https://192.0.2.1:8443/path,script-path=a.js
`, `$done();`)
	request := httptest.NewRequest(http.MethodGet, "https://192.0.2.1:8443/path", nil)
	request.Host = "host.example:8443"
	request.TLS = &tls.ConnectionState{ServerName: "sni.example"}
	for _, want := range []string{"first", "second", "third"} {
		_, script := engine.matchScript("http-request", request)
		if script == nil || script.Name != want {
			t.Fatalf("first-match order: %+v want %s", script, want)
		}
		engine.options.Modules[0].Scripts = engine.options.Modules[0].Scripts[1:]
	}
	engine.options.Modules[0].Hostnames = []string{"sni.example:8443"}
	if len(engine.forConnection("unrelated.example", 8443).options.Modules) != 0 {
		t.Fatal("script hostname aliases expanded the admitted module scope")
	}
}

func TestHTTPFullHeaderModePreservesRepeatedFields(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
request=type=http-request,pattern=.,script-path=a.js,full-header-mode=true
response=type=http-response,pattern=.,script-path=a.js,full-header-mode=true
`, `const headers = ($script.type === "http-request" ? $request : $response).headers;
if (!Array.isArray(headers)) throw Error("full headers missing");
headers.push({field:"X-Processed",value:"yes"}); $done({headers});`)
	request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	request.Header["X-Repeat"] = []string{"first", "second"}
	if _, err := engine.processRequest(&plugin.Exchange{Request: request, Client: http.DefaultClient}); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("X-Processed") != "yes" || !reflect.DeepEqual(request.Header.Values("X-Repeat"), []string{"first", "second"}) {
		t.Fatalf("request fields lost: %v", request.Header)
	}
	response := &http.Response{Request: request, StatusCode: 200, Header: http.Header{"Set-Cookie": {"one=1; Path=/", "two=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT"}}, Body: http.NoBody}
	cookies := response.Header.Values("Set-Cookie")
	if err := engine.processResponse(response, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("X-Processed") != "yes" || !reflect.DeepEqual(response.Header.Values("Set-Cookie"), cookies) {
		t.Fatalf("response cookies lost: %v", response.Header)
	}
}

func TestScriptBodyRules(t *testing.T) {
	t.Run("response requires-body", func(t *testing.T) {
		engine := testProxyEngine(t, "[Script]\na=type=http-response,pattern=.,script-path=a.js", `$done({body:"invalid"});`)
		response := &http.Response{Request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil), StatusCode: 200, Header: make(http.Header), Body: http.NoBody}
		if err := engine.processResponse(response, http.DefaultClient); !errors.Is(err, errScriptAbort) {
			t.Fatalf("unbuffered body did not abort: %v", err)
		}
	})
	for _, framing := range []string{"chunked", "expect"} {
		t.Run(framing, func(t *testing.T) {
			engine := testProxyEngine(t, "[Script]\na=type=http-request,pattern=.,requires-body=true,script-path=a.js", `$done({body:"replacement",headers:{"X-Processed":"yes"}});`)
			request := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("original"))
			if framing == "chunked" {
				request.TransferEncoding = []string{"chunked"}
			} else {
				request.Header.Set("Expect", "100-continue")
			}
			if _, err := engine.processRequest(&plugin.Exchange{Request: request, Client: http.DefaultClient}); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(request.Body)
			request.Body.Close()
			if err != nil || string(body) != "original" || request.Header.Get("X-Processed") != "yes" {
				t.Fatalf("framing semantics: body=%q headers=%v err=%v", body, request.Header, err)
			}
		})
	}
}

func TestDisabledScriptsDoNotLoadOrSchedule(t *testing.T) {
	module, err := loadModuleContents(t.Context(), `[Script]
http=type=http-request,pattern=.,script-path=missing.js,enable=false
cron=type=cron,cronexp="* * * * *",script-path=missing.js,enable=false
dns=type=dns,script-path=missing.js,enable=false`, "/module", nil, nil)
	if err != nil || len(module.Scripts)+len(module.TaskScripts) != 0 {
		t.Fatalf("disabled scripts: %+v %v", module, err)
	}
}
