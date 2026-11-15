// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/miekg/dns"
)

func TestScriptIsolationInheritance(t *testing.T) {
	for _, instance := range []string{"", "true", "false"} {
		for _, module := range []string{"", "true", "false"} {
			for _, override := range []string{"", "true", "false"} {
				body := "surge {"
				if instance != "" {
					body += "isolate_lan: " + instance
				}
				body += " module { test { link: 'file:test'"
				if module != "" {
					body += " isolate_lan: " + module
				}
				if override != "" {
					body += " script {name: script isolate_lan: " + override + "}"
				}
				sections, err := config_parser.Parse(body + "}}}")
				if err != nil {
					t.Fatal(err)
				}
				conf, err := ParseConfig(sections[0])
				if err != nil || conf.IsolateLAN != (instance != "false") {
					t.Fatalf("config=%+v error=%v", conf, err)
				}
				want := conf.IsolateLAN
				if module != "" {
					want = module == "true"
				}
				if override != "" {
					want = override == "true"
				}
				e := &Engine{options: EngineOptions{IsolateLAN: conf.IsolateLAN}}
				for _, kind := range []string{"http-request", "http-response", "dns", "cron", "generic"} {
					line := "[Script]\nscript=type=" + kind + ",script-path=test.js"
					if strings.HasPrefix(kind, "http-") {
						line += ",pattern=."
					} else if kind == "cron" {
						line += ",cronexp=* * * * *"
					}
					m, err := Parse(line, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := applyModuleIsolation(m, conf.Modules[0]); err != nil {
						t.Fatal(err)
					}
					scripts := m.Scripts
					if len(scripts) == 0 {
						scripts = m.TaskScripts
					}
					script := &scripts[0]
					if script.IsolateLANSet != (module != "" || override != "") || e.isolateLAN(script) != want || len(m.Warnings)+len(m.Ignored) != 0 {
						t.Fatalf("config=%s type=%s script=%+v", body, kind, script)
					}
					calls := 0
					ctx := context.WithValue(t.Context(), scriptScopeKey{}, func(context.Context) ScriptScope {
						calls++
						return testDeviceScope
					})
					scope := e.requestScope(ctx, script)
					if want && (scope != testDeviceScope || calls != 1) || !want && (scope != testLocalScope || calls != 0) {
						t.Fatalf("isolation=%t scope=%+v identity calls=%d", want, scope, calls)
					}
				}
			}
		}
	}
}

func TestScriptIsolationIsNotASurgeParameter(t *testing.T) {
	for _, value := range []string{"true", "false", "invalid"} {
		var warnings, ignored []string
		script, err := parseScript("script=type=generic,script-path=test.js,isolate-lan="+value, &warnings, &ignored)
		if err != nil || script.IsolateLANSet || len(warnings) != 1 || !strings.Contains(warnings[0], "unsupported parameter") {
			t.Fatalf("Surge parameter changed host policy: %+v %v %v", script, warnings, err)
		}
	}
}

func TestScriptScopeRejectsInvalidCombinations(t *testing.T) {
	store, err := openRuntimeStore("")
	if err != nil {
		t.Fatal(err)
	}
	if !store.write(t.Context(), testLocalScope, "secret", "local", false) || !store.write(t.Context(), testDeviceScope, "secret", "device", false) {
		t.Fatal("seed scopes")
	}
	for _, scope := range []ScriptScope{
		{}, {Kind: ScriptScopeUnknown, MAC: testDeviceMAC},
		{Kind: ScriptScopeLocal, MAC: testDeviceMAC},
		{Kind: ScriptScopeDevice}, {Kind: ScriptScopeDevice, MAC: [6]byte{1, 0, 0, 0, 0, 1}},
		{Kind: 255, MAC: testDeviceMAC},
	} {
		if scope.valid() || scope.key() != "" || scope.name() != "unknown" || scope.deviceName() != "" {
			t.Fatalf("invalid scope gained identity: %+v", scope)
		}
		if got, err := store.read(t.Context(), scope, "secret"); err != nil || got != nil || store.write(t.Context(), scope, "secret", "bad", false) || store.write(t.Context(), scope, "secret", "", true) {
			t.Fatalf("invalid scope accessed storage: %+v %v %v", scope, got, err)
		}
	}
}

func TestHTTPScriptLocalAndSharedScopes(t *testing.T) {
	for _, isolate := range []bool{true, false} {
		t.Run(fmt.Sprint(isolate), func(t *testing.T) {
			module := moduleScopeModule(t, "http", "scope.test", `[Script]
request=type=http-request,pattern=.,script-path=request.js
response=type=http-response,pattern=.,script-path=response.js`, map[string]string{
				"request":  `$persistentStore.write(String(Number($persistentStore.read("count") || 0)+1), "count"); $done();`,
				"response": `$done({headers:{"X-Count":String($persistentStore.read("count"))}});`,
			})
			e := moduleScopeEngine(t, module)
			e.options.IsolateLAN = isolate
			devices := newTestDevices()
			e.options.Devices = devices
			calls := 0
			devices.identify = func(_ context.Context, _ netip.Addr, mac [6]byte) [6]byte { calls++; return mac }
			for i, test := range []struct {
				origin plugin.SourceOrigin
				mac    [6]byte
				want   string
			}{
				{plugin.SourceLocal, [6]byte{}, "1"},
				{plugin.SourceLAN, testDeviceMAC, "1"},
				{plugin.SourceLocal, testDeviceMAC, "2"},
				{plugin.SourceLAN, [6]byte{2, 0, 0, 0, 0, 2}, "1"},
				{plugin.SourceLAN, testDeviceMAC, "2"},
				{plugin.SourceLAN, [6]byte{}, "null"},
				{plugin.SourceUnknown, testDeviceMAC, "null"},
			} {
				request := httptest.NewRequest("GET", "https://scope.test/", nil)
				request.Header.Set("X-Device-MAC", testDeviceName)
				flow := plugin.Flow{Host: "scope.test", Port: 443, SourceOrigin: test.origin, SourceMAC: test.mac}
				response, err := e.Wrap(flow, func(exchange *plugin.Exchange) (*plugin.Response, error) {
					return exchange.NewResponse(&http.Response{StatusCode: 200, Request: exchange.Request.Head, Header: make(http.Header), Body: http.NoBody}), nil
				})(&plugin.Exchange{Request: plugin.NewRequest(request, e.options.BodyMemory), Client: http.DefaultClient})
				if err != nil {
					t.Fatal(err)
				}
				response.Close()
				want := test.want
				if !isolate {
					want = fmt.Sprint(i + 1)
				}
				if got := response.Head.Header.Get("X-Count"); got != want {
					t.Fatalf("origin=%v mac=%v count=%s want=%s", test.origin, test.mac, got, want)
				}
			}
			if isolate && calls != 4 || !isolate && calls != 0 {
				t.Fatalf("unnecessary identity queries: %d", calls)
			}
		})
	}
}

func TestDNSScriptLocalAndSharedCache(t *testing.T) {
	for _, isolate := range []bool{true, false} {
		t.Run(fmt.Sprint(isolate), func(t *testing.T) {
			module := moduleScopeModule(t, "dns", "", "[Host]\nscript.test=script:answer\n[Script]\nanswer=type=dns,script-path=answer.js", map[string]string{
				"answer": `$done({addresses:["192.0.2.1"],ttl:60});`,
			})
			e := moduleScopeEngine(t, module)
			e.options.IsolateLAN = isolate
			e.options.Devices = newTestDevices()
			handler := e.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				t.Fatal("unexpected DNS fallback")
				return nil, nil
			})
			for i, test := range []struct {
				origin plugin.SourceOrigin
				mac    [6]byte
				cached bool
			}{
				{plugin.SourceLocal, [6]byte{}, false},
				{plugin.SourceLocal, [6]byte{}, true},
				{plugin.SourceLAN, testDeviceMAC, false},
				{plugin.SourceLAN, testDeviceMAC, true},
				{plugin.SourceUnknown, testDeviceMAC, false},
				{plugin.SourceUnknown, testDeviceMAC, false},
			} {
				query := hostDNSRequest(t, "script.test.", dns.TypeA)
				query.SourceOrigin, query.SourceMAC = test.origin, test.mac
				response, err := handler(t.Context(), query)
				want := test.cached
				if !isolate {
					want = i != 0
				}
				if err != nil || response.Cached != want {
					t.Fatalf("origin=%v cached=%+v want=%t error=%v", test.origin, response, want, err)
				}
			}
		})
	}
}
