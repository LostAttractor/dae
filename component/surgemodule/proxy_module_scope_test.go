// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func moduleScopeModule(t *testing.T, name, hosts, rules string, sources map[string]string) *Module {
	t.Helper()
	text := "#!name=" + name + "\n"
	if hosts != "" {
		text += "[MITM]\nhostname=" + hosts + "\n"
	}
	m, err := Parse(text+rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Warnings) != 0 {
		t.Fatalf("unexpected module warnings: %v", m.Warnings)
	}
	for i := range m.Scripts {
		source, ok := sources[m.Scripts[i].Name]
		if !ok {
			t.Fatalf("missing source for script %s", m.Scripts[i].Name)
		}
		m.Scripts[i].Source = source
	}
	return m
}

func moduleScopeEngine(t *testing.T, modules ...*Module) *Engine {
	t.Helper()
	base, _ := integrationEngine(t, nil, nil)
	options := base.options
	options.Modules = modules
	engine, err := NewEngine(options)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

type moduleScopeRequest struct {
	host, path, body string
	header           http.Header
}

// Use the public connection handler so response processing sees the same
// connection scope even after a request changes its URL or Host header.
func moduleScopeExchange(t *testing.T, engine *Engine, host string, port uint16) (*httptest.ResponseRecorder, *moduleScopeRequest) {
	t.Helper()
	requests := make(chan moduleScopeRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request: %v", err)
		}
		requests <- moduleScopeRequest{host: r.Host, path: r.URL.Path, body: string(body), header: r.Header.Clone()}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"value":1}`)
	}))
	defer upstream.Close()
	handler, closeTransport := engine.Handler("http", host, port, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	})
	defer closeTransport()
	authority := host
	if port != 80 {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	request := httptest.NewRequest(http.MethodPost, "http://"+authority+"/source", strings.NewReader("original request"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	select {
	case observed := <-requests:
		return response, &observed
	default:
		return response, nil
	}
}

func TestProxyModuleScopeBroadRules(t *testing.T) {
	for _, rule := range []struct {
		name, rules, source                       string
		requestBody, responseBody, path           string
		requestHeader, responseHeader, isMapLocal bool
	}{
		{
			name:        "request-script",
			rules:       "[Script]\nrule=type=http-request,pattern=.,requires-body=1,script-path=rule.js\n",
			source:      `$done({headers:{...$request.headers,"X-Scope-Request":"changed"},body:"module request"});`,
			requestBody: "module request", requestHeader: true,
		},
		{
			name:         "response-script",
			rules:        "[Script]\nrule=type=http-response,pattern=.,requires-body=1,script-path=rule.js\n",
			source:       `$done({headers:{...$response.headers,"X-Scope-Response":"changed"},body:'{"value":99}'});`,
			responseBody: `{"value":99}`, responseHeader: true,
		},
		{
			name:         "map-local",
			rules:        "[Map Local]\n. data-type=text data=\"module response\" status-code=201\n",
			responseBody: "module response", isMapLocal: true,
		},
		{
			name:  "url-rewrite",
			rules: "[URL Rewrite]\n^http://.*/source$ http://a.test/rewritten header\n",
			path:  "/rewritten",
		},
		{
			name:          "header-rewrite",
			rules:         "[Header Rewrite]\nhttp-request . header-add X-Scope-Request changed\nhttp-response . header-add X-Scope-Response changed\n",
			requestHeader: true, responseHeader: true,
		},
		{
			name:         "body-rewrite",
			rules:        "[Body Rewrite]\nhttp-response-jq . '.value = 99'\n",
			responseBody: `{"value":99}`,
		},
	} {
		t.Run(rule.name, func(t *testing.T) {
			for _, scope := range []struct {
				name, hosts string
				active      bool
			}{
				{"matching-module", "a.test:0", true},
				{"foreign-module", "b.test:0", false},
				{"without-mitm", "", false},
			} {
				t.Run(scope.name, func(t *testing.T) {
					candidate := moduleScopeModule(t, "candidate", scope.hosts, rule.rules, map[string]string{"rule": rule.source})
					anchor := moduleScopeModule(t, "anchor", "a.test:0", "", nil)
					engine := moduleScopeEngine(t, candidate, anchor)
					if !engine.Match("a.test", 80) {
						t.Fatal("anchor module did not select the connection")
					}
					response, observed := moduleScopeExchange(t, engine, "a.test", 80)
					wantStatus, wantBody := http.StatusOK, `{"value":1}`
					if scope.active {
						if rule.responseBody != "" {
							wantBody = rule.responseBody
						}
						if rule.isMapLocal {
							wantStatus = http.StatusCreated
						}
					}
					if response.Code != wantStatus || response.Body.String() != wantBody {
						t.Errorf("response=%d %q; want %d %q", response.Code, response.Body.String(), wantStatus, wantBody)
					}
					if got := response.Header().Get("X-Scope-Response"); (got == "changed") != (scope.active && rule.responseHeader) {
						t.Errorf("unexpected response rewrite header %q", got)
					}
					if scope.active && rule.isMapLocal {
						if observed != nil {
							t.Fatal("Map Local contacted upstream")
						}
						return
					}
					if observed == nil {
						t.Fatal("request did not reach upstream")
					}
					wantRequestBody, wantPath := "original request", "/source"
					if scope.active {
						if rule.requestBody != "" {
							wantRequestBody = rule.requestBody
						}
						if rule.path != "" {
							wantPath = rule.path
						}
					}
					if observed.host != "a.test" || observed.path != wantPath || observed.body != wantRequestBody {
						t.Errorf("unexpected upstream request: %+v", observed)
					}
					if got := observed.header.Get("X-Scope-Request"); (got == "changed") != (scope.active && rule.requestHeader) {
						t.Errorf("unexpected request rewrite header %q", got)
					}
				})
			}
		})
	}
}

func TestProxyModuleScopeExclusionIsLocal(t *testing.T) {
	module := func(name, hosts string) *Module {
		return moduleScopeModule(t, name, hosts, `[Script]
request=type=http-request,pattern=.,script-path=request.js
response=type=http-response,pattern=.,script-path=response.js
[Header Rewrite]
http-request . header-add X-Header-`+name+` yes
http-response . header-add X-Header-`+name+` yes
[Body Rewrite]
http-response-jq . '.`+name+` = true'
`, map[string]string{
			"request":  `$done({headers:{...$request.headers,"X-Script-` + name + `":"yes"}});`,
			"response": `$done({headers:{...$response.headers,"X-Script-` + name + `":"yes"}});`,
		})
	}
	engine := moduleScopeEngine(t, module("a", "-excluded.test:0,*.test:0"), module("b", "excluded.test:0"))
	for _, test := range []struct{ host, allowed, excluded string }{
		{"excluded.test", "b", "a"},
		{"ordinary.test", "a", "b"},
	} {
		t.Run(test.host, func(t *testing.T) {
			if !engine.Match(test.host, 80) {
				t.Fatal("one module's exclusion suppressed another module's allowlist")
			}
			response, observed := moduleScopeExchange(t, engine, test.host, 80)
			if response.Code != http.StatusOK || observed == nil {
				t.Fatalf("request failed: %d %q", response.Code, response.Body.String())
			}
			assertBodyRewriteJSON(t, response.Body.Bytes(), `{"value":1,"`+test.allowed+`":true}`)
			for _, headers := range []http.Header{observed.header, response.Header()} {
				for _, kind := range []string{"Header", "Script"} {
					if headers.Get("X-"+kind+"-"+test.allowed) != "yes" || headers.Get("X-"+kind+"-"+test.excluded) != "" {
						t.Errorf("wrong module processed %s headers: %v", kind, headers)
					}
				}
			}
		})
	}
}

func TestProxyModuleScopeDoesNotFollowRewrite(t *testing.T) {
	for _, rewrite := range []struct{ name, rules, source string }{
		{"url", "[URL Rewrite]\n^http://a\\.test/(.*) http://b.test/$1 header\n", ""},
		{"host-header", "[Header Rewrite]\nhttp-request . header-replace Host b.test\n", ""},
		{"request-script", "[Script]\nrequest=type=http-request,pattern=.,script-path=request.js\n", `$done({url:"http://b.test/source",headers:{...$request.headers,Host:"b.test"}});`},
	} {
		t.Run(rewrite.name, func(t *testing.T) {
			a := moduleScopeModule(t, "a", "a.test:0", rewrite.rules+`[Script]
response=type=http-response,pattern=.,requires-body=1,script-path=response.js
`, map[string]string{
				"request":  rewrite.source,
				"response": `const body=JSON.parse($response.body); body.value++; $done({headers:{...$response.headers,"X-Scope-Response":"a"},body:JSON.stringify(body)});`,
			})
			b := moduleScopeModule(t, "b", "b.test:0", `[Map Local]
. data-type=text data="module b" status-code=201
[Script]
response=type=http-response,pattern=.,requires-body=1,script-path=response.js
[Header Rewrite]
http-request . header-add X-Foreign request
http-response . header-add X-Foreign response
[Body Rewrite]
http-response-jq . '.foreign = true'
`, map[string]string{"response": `$done({body:"foreign response script"});`})
			// B comes first so a broad pattern cannot be hidden by A's script.
			engine := moduleScopeEngine(t, b, a)
			response, observed := moduleScopeExchange(t, engine, "a.test", 80)
			if response.Code != http.StatusOK || observed == nil {
				t.Fatalf("rewrite activated foreign module: %d %q", response.Code, response.Body.String())
			}
			if observed.host != "b.test" || observed.path != "/source" || observed.header.Get("X-Foreign") != "" {
				t.Errorf("unexpected rewritten request: %+v", observed)
			}
			if response.Header().Get("X-Scope-Response") != "a" || response.Header().Get("X-Foreign") != "" {
				t.Errorf("response lost original connection scope: %v", response.Header())
			}
			assertBodyRewriteJSON(t, response.Body.Bytes(), `{"value":2}`)
			// The shared engine must remain usable for a new connection to B.
			response, observed = moduleScopeExchange(t, engine, "b.test", 80)
			if response.Code != http.StatusCreated || response.Body.String() != "module b" || observed != nil {
				t.Fatalf("A's handler changed B's connection scope: %d %q upstream=%+v", response.Code, response.Body.String(), observed)
			}
		})
	}
}

func TestProxyModuleScopeConnectionPort(t *testing.T) {
	a := moduleScopeModule(t, "a", "a.test:8443", "[Map Local]\n. data-type=text data=\"a\"\n", nil)
	b := moduleScopeModule(t, "b", "a.test:9443", "[Map Local]\n. data-type=text data=\"b\"\n", nil)
	engine := moduleScopeEngine(t, a, b)
	for _, test := range []struct {
		port uint16
		body string
	}{{8443, "a"}, {9443, "b"}} {
		t.Run(strconv.Itoa(int(test.port)), func(t *testing.T) {
			response, observed := moduleScopeExchange(t, engine, "a.test", test.port)
			if response.Code != http.StatusOK || response.Body.String() != test.body || observed != nil {
				t.Fatalf("connection port selected wrong module: %d %q upstream=%+v", response.Code, response.Body.String(), observed)
			}
		})
	}
}

func TestProxyModuleScopeSharesRuntimeAndCapacity(t *testing.T) {
	module := moduleScopeModule(t, "shared", "a.test:0,b.test:0", "[Script]\nrequest=type=http-request,pattern=.,script-path=request.js\n", map[string]string{
		"request": `const value=Number($persistentStore.read("scope-counter")||"0")+1; $persistentStore.write(String(value),"scope-counter"); $done({response:{status:200,body:String(value)}});`,
	})
	engine := moduleScopeEngine(t, module)
	var handlers []http.Handler
	for _, host := range []string{"a.test", "b.test"} {
		handler, closeTransport := engine.Handler("http", host, 80, func(context.Context, string, string) (net.Conn, error) {
			t.Error("synthetic script contacted upstream")
			return nil, context.Canceled
		})
		t.Cleanup(closeTransport)
		handlers = append(handlers, handler)
	}
	// Saturating the shared engine must also block both connection handlers.
	for range cap(engine.slots) {
		engine.slots <- struct{}{}
	}
	for i, host := range []string{"a.test", "b.test"} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil).WithContext(ctx)
		response := httptest.NewRecorder()
		handlers[i].ServeHTTP(response, request)
		cancel()
		if response.Code != http.StatusBadGateway || len(engine.slots) != cap(engine.slots) {
			t.Fatalf("connection bypassed shared script capacity: status=%d slots=%d", response.Code, len(engine.slots))
		}
	}
	for range cap(engine.slots) {
		<-engine.slots
	}
	// An in-memory persistent store is owned by the runtime; the second
	// connection must see the first connection's write after capacity returns.
	for i, host := range []string{"a.test", "b.test"} {
		response := httptest.NewRecorder()
		handlers[i].ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
		if response.Code != http.StatusOK || response.Body.String() != strconv.Itoa(i+1) || len(engine.slots) != 0 {
			t.Fatalf("connection lost shared runtime or leaked a slot: status=%d body=%q slots=%d", response.Code, response.Body.String(), len(engine.slots))
		}
	}
}
