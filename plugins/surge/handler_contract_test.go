// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
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
	controlledRequest := plugin.NewRequest(request, engine.options.BodyMemory)
	t.Cleanup(func() { _ = controlledRequest.Body().Close() })
	if _, err := engine.processRequest(&plugin.Exchange{Request: controlledRequest, Client: http.DefaultClient}); err != nil {
		t.Fatal(err)
	}
	request = forwardTestRequest(t, controlledRequest)
	if request.Header.Get("X-Processed") != "yes" || !reflect.DeepEqual(request.Header.Values("X-Repeat"), []string{"first", "second"}) {
		t.Fatalf("request fields lost: %v", request.Header)
	}
	response := &http.Response{Request: request, StatusCode: 200, Header: http.Header{"Set-Cookie": {"one=1; Path=/", "two=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT"}}, Body: http.NoBody}
	cookies := response.Header.Values("Set-Cookie")
	controlledResponse := plugin.NewResponse(response, engine.options.BodyMemory)
	t.Cleanup(func() { _ = controlledResponse.Close() })
	if err := engine.processResponse(controlledResponse, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	response = takeTestResponse(t, controlledResponse)
	if response.Header.Get("X-Processed") != "yes" || !reflect.DeepEqual(response.Header.Values("Set-Cookie"), cookies) {
		t.Fatalf("response cookies lost: %v", response.Header)
	}
}

func TestScriptBodyRules(t *testing.T) {
	t.Run("response requires-body", func(t *testing.T) {
		engine := testProxyEngine(t, "[Script]\na=type=http-response,pattern=.,script-path=a.js", `$done({body:"invalid"});`)
		response := &http.Response{Request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil), StatusCode: 200, Header: make(http.Header), Body: http.NoBody}
		controlledResponse := plugin.NewResponse(response, engine.options.BodyMemory)
		t.Cleanup(func() { _ = controlledResponse.Close() })
		if err := engine.processResponse(controlledResponse, http.DefaultClient); !errors.Is(err, errScriptAbort) {
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
			controlledRequest := plugin.NewRequest(request, engine.options.BodyMemory)
			t.Cleanup(func() { _ = controlledRequest.Body().Close() })
			if _, err := engine.processRequest(&plugin.Exchange{Request: controlledRequest, Client: http.DefaultClient}); err != nil {
				t.Fatal(err)
			}
			request = forwardTestRequest(t, controlledRequest)
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

type bodylessStatusSource struct {
	io.Reader
	reads, closes int
}

func (s *bodylessStatusSource) Read(p []byte) (int, error) {
	s.reads++
	return s.Reader.Read(p)
}
func (s *bodylessStatusSource) Close() error { s.closes++; return nil }

func TestHTTPStatusOmitsBodyPreservesRepresentation(t *testing.T) {
	for _, status := range []int{http.StatusNotModified, http.StatusNoContent} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("status=%d/replace=%t", status, replace), func(t *testing.T) {
				module := "[Script]\nrewrite=type=http-response,pattern=.,script-path=a.js"
				bodyResult := ""
				if replace {
					module += ",requires-body=true"
					bodyResult = `,body:"replacement"`
				}
				engine := testProxyEngine(t, module, fmt.Sprintf(`$done({status:%d,trailers:{"X-Script":"tail"}%s});`, status, bodyResult))
				budget := membuffer.NewBudget(8 << 20)
				engine.options.BodyMemory = budget
				encoded := encodeRuntimeHTTPBody(t, []byte("original"), "gzip")
				source := &bodylessStatusSource{Reader: strings.NewReader(string(encoded))}
				request := httptest.NewRequest(http.MethodGet, "https://example.com/item", nil)
				request.Header.Set("If-None-Match", `"original"`)
				preserved := http.Header{
					"Etag": {`"original"`}, "Last-Modified": {"Mon, 26 Oct 2026 00:00:00 GMT"},
					"Content-Encoding": {"gzip"}, "Repr-Digest": {"sha-256=:representation:"},
				}
				header := preserved.Clone()
				header.Set("Content-Digest", "sha-256=:content:")
				header.Set("Content-MD5", "content")
				header.Set("Trailer", "X-Upstream")
				header.Set("Cache-Control", "max-age=60")
				response := plugin.NewResponse(&http.Response{
					Request: request, StatusCode: http.StatusOK, Header: header,
					Body: source, ContentLength: int64(len(encoded)),
					Trailer: http.Header{"X-Upstream": {"tail"}},
				}, budget)
				defer response.Close()
				response.SetDelivery(plugin.DeliveryStreaming)
				if err := engine.processResponse(response, nil); err != nil {
					t.Fatal(err)
				}
				wire := takeTestResponse(t, response)
				for name, values := range preserved {
					want := values
					if replace {
						want = nil
					}
					if got := wire.Header.Values(name); !reflect.DeepEqual(got, want) {
						t.Errorf("%s=%v want=%v", name, got, want)
					}
				}
				for _, name := range []string{"Transfer-Encoding", "Trailer", "Content-Digest", "Content-MD5"} {
					if wire.Header.Get(name) != "" {
						t.Errorf("bodyless response retained %s", name)
					}
				}
				if len(wire.Trailer) != 0 || len(wire.TransferEncoding) != 0 || wire.Header.Get("Cache-Control") != "max-age=60" {
					t.Fatal("incorrect metadata for a bodyless status", wire)
				}
				wantDelivery := plugin.DeliveryStreaming
				if replace {
					wantDelivery = plugin.DeliveryDefault
				}
				if response.Head.Body != nil || response.Delivery() != wantDelivery || !replace && source.reads != 0 || source.closes != 1 {
					t.Fatal("incorrect body ownership or delivery", source.reads, source.closes)
				}
				if status == http.StatusNoContent && (wire.ContentLength != 0 || wire.Header.Get("Content-Length") != "") || status == http.StatusNotModified && !replace && wire.ContentLength != int64(len(encoded)) {
					t.Fatal("incorrect content length for a bodyless status", wire)
				}
				data, err := io.ReadAll(wire.Body)
				_ = wire.Body.Close()
				_ = response.Close()
				if err != nil || len(data) != 0 || wire.StatusCode != status || source.closes != 1 || budget.Status().Used != 0 {
					t.Fatal(string(data), err, wire.StatusCode, source.closes, budget.Status())
				}
			})
		}
	}
}

func TestHTTPMessageBodyOwnershipAndDelivery(t *testing.T) {
	for _, tc := range []struct {
		name, method, source, want string
		status                     int
		requiresBody               bool
		delivery                   plugin.Delivery
	}{
		{"headers-only", http.MethodGet, `$done({});`, "original", 200, false, plugin.DeliveryStreaming},
		{"snapshot", http.MethodGet, `$done({});`, "original", 200, true, plugin.DeliveryStreaming},
		{"replacement", http.MethodGet, `$done({body:"rewritten"});`, "rewritten", 200, true, plugin.DeliveryDefault},
		{"head", http.MethodHead, `$done({});`, "", 200, true, plugin.DeliveryStreaming},
		{"not-modified", http.MethodGet, `$done({});`, "", 304, true, plugin.DeliveryStreaming},
		{"status-removes-body", http.MethodGet, `$done({status:204});`, "", 200, false, plugin.DeliveryStreaming},
	} {
		t.Run(tc.name, func(t *testing.T) {
			module := "[Script]\nrewrite=type=http-response,pattern=.,script-path=a.js"
			if tc.requiresBody {
				module += ",requires-body=true"
			}
			engine := testProxyEngine(t, module, tc.source)
			budget := membuffer.NewBudget(1 << 20)
			engine.options.BodyMemory = budget
			body := io.NopCloser(strings.NewReader("original"))
			if !responseHasBody(tc.method, tc.status) {
				body = http.NoBody
			}
			response := plugin.NewResponse(&http.Response{
				Request:    httptest.NewRequest(tc.method, "https://example.com/", nil),
				StatusCode: tc.status, Header: http.Header{"Etag": {`"original"`}},
				ContentLength: 8, Body: body,
			}, budget)
			defer response.Close()
			response.SetDelivery(plugin.DeliveryStreaming)
			if err := engine.processResponse(response, nil); err != nil {
				t.Fatal(err)
			}
			if response.Head.Body != nil || response.Delivery() != tc.delivery {
				t.Fatalf("incorrect body ownership or delivery policy: %+v delivery=%v", response.Head, response.Delivery())
			}
			if tc.delivery == plugin.DeliveryStreaming && (response.Head.Header.Get("Etag") != `"original"` || response.Head.ContentLength != 8) {
				t.Fatal("unchanged representation lost validators or content length")
			}
			if replaced := tc.name == "replacement"; (response.Head.Header.Get("Etag") == "") != replaced {
				t.Fatal("representation validators do not match body replacement semantics")
			}
			wire := takeTestResponse(t, response)
			got, err := io.ReadAll(wire.Body)
			wire.Body.Close()
			if err != nil || string(got) != tc.want || budget.Status().Used != 0 {
				t.Fatalf("body=%q err=%v budget=%+v", got, err, budget.Status())
			}
		})
	}
}
