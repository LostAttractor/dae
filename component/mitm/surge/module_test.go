// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModuleArgumentsAndHTTPPatterns(t *testing.T) {
	m, err := Parse(`#!name=Example
#!arguments=语言:zh,启用:true
[Script]
response = type=http-response,pattern=^https://api\.example\.com/(?!ads/)\w{1,3}$,requires-body=1,binary-body-mode=true,max-size=-1,argument="{"language":"{{{语言}}}","enabled":{{{启用}}},"values":[1,2]}",timeout=1.5,script-path=scripts/response.js
[MITM]
hostname = %APPEND% -ads.example.com, *.example.com
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "Example" || len(m.Scripts) != 1 || len(m.Warnings) != 0 {
		t.Fatalf("unexpected module: %+v", m)
	}
	script := m.Scripts[0]
	if script.Argument != `{"language":"zh","enabled":true,"values":[1,2]}` {
		t.Fatalf("argument=%q", script.Argument)
	}
	if !script.RequiresBody || !script.BinaryBodyMode || script.MaxSize != -1 || script.Timeout != 1500*time.Millisecond {
		t.Fatalf("unexpected script: %+v", script)
	}
	if !script.Match("https://api.example.com/abc") || script.Match("https://api.example.com/ads/") {
		t.Fatal("lookahead or comma-containing quantifier did not match correctly")
	}
	if !m.MatchHostname("API.EXAMPLE.COM.") || m.MatchHostname("ads.example.com") {
		t.Fatal("MITM wildcard/exclusion mismatch")
	}
}

func TestModuleQuotedArguments(t *testing.T) {
	m, err := Parse(`#!arguments=lang:zh
[Script]
a = type=http-request,pattern=.,script-path=a.js,argument="a,b=c,{{{lang}}}",requires-body=0
b = type=http-request,pattern=.,script-path=b.js,argument="{\"x\":1,\"y\":2}"
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Scripts[0].Argument != "a,b=c,zh" || m.Scripts[1].Argument != `{"x":1,"y":2}` {
		t.Fatalf("unexpected quoted arguments: %+v", m.Scripts)
	}
	if m.Scripts[0].MaxSize != DefaultScriptMaxSize || m.Scripts[0].Timeout != 0 {
		t.Fatal("expected default body limit and inherited timeout")
	}
}

func TestModuleRejectsMalformedScripts(t *testing.T) {
	for _, options := range []string{
		"type=http-request,script-path=a.js",
		"type=http-request,pattern=(,script-path=a.js",
		"type=http-request,pattern=.,script-path=a.js,engine=unknown",
		"type=http-request,pattern=.,script-path=a.js,max-size=-2",
		"type=http-request,pattern=.,script-path=a.js,timeout=NaN",
		"type=http-request,pattern=.,script-path=a.js,timeout=+Inf",
		"type=http-request,pattern=.,script-path=a.js,timeout=0",
		"type=http-request,pattern=.,script-path=a.js,timeout=301",
		"type=http-request,pattern=.,script-path=a.js,timeout=1,timeout=2",
		"type=http-request,pattern=.,script-path=a.js,argument=\"unfinished",
		"type=http-request,pattern=.,script-path=a.js,argument={{{missing}}}",
	} {
		t.Run(options, func(t *testing.T) {
			if _, err := Parse("[Script]\na = "+options, nil); err == nil {
				t.Fatal("accepted invalid script")
			}
		})
	}
}

func TestModuleScriptParameterDiagnostics(t *testing.T) {
	for _, test := range []struct {
		option   string
		ignored  int
		warnings int
		invalid  bool
		disabled bool
	}{
		{option: "script-update-interval=not-a-duration", ignored: 1},
		{option: "debug=not-a-boolean", ignored: 1},
		{option: "enable=false", disabled: true},
		{option: "enable=not-a-boolean", invalid: true},
		{option: "full-header-mode=not-a-boolean", invalid: true},
		{option: "unknown-option=true", warnings: 1},
		{option: "requires-body=maybe", invalid: true},
	} {
		t.Run(test.option, func(t *testing.T) {
			module, err := Parse("[Script]\na = type=http-request,pattern=.,script-path=a.js,"+test.option, nil)
			if test.invalid {
				if err == nil {
					t.Fatal("accepted an invalid supported parameter")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantScripts := 1
			if test.disabled {
				wantScripts = 0
			}
			if len(module.Scripts) != wantScripts || len(module.Ignored) != test.ignored || len(module.Warnings) != test.warnings {
				t.Fatalf("unexpected script or diagnostics: %+v", module)
			}
		})
	}
}

func TestModuleWarnsForUnsupportedFeatures(t *testing.T) {
	m, err := Parse(`[Rule]
DOMAIN,example.com,REJECT
DOMAIN,example.org,REJECT
[General]
force-http-engine-hosts = example.com
[Script]
scheduled = type=cron,cronexp="0 * * * *",script-path=cron.js
headers = type=http-request,pattern=.,script-path=a.js,full-header-mode=true,engine=jsc
webview1 = type=http-request,pattern=.,script-path=a.js,engine=webview
webview2 = type=http-response,pattern=.,script-path=a.js,engine=webview
[MITM]
skip-server-cert-verify = true
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Scripts) != 3 || len(m.Rules) != 2 || len(m.Warnings) != 5 || len(m.Ignored) != 0 {
		t.Fatalf("expected three scripts, two domain rules, five deduplicated warnings and no ignored parameters, got %+v", m)
	}
}

func TestModuleHostnameOrderAndPorts(t *testing.T) {
	m, err := Parse(`[MITM]
hostname = ignored.example
hostname = *.example.com
hostname = %INSERT% -ads.example.com
hostname = %APPEND% api.example.org:8443, any.example.org:0, node?.example.net
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host  string
		match bool
	}{
		{"ads.example.com", false}, {"www.example.com", true}, {"example.com", false},
		{"www.example.com:443", true}, {"www.example.com:8443", false},
		{"api.example.org:8443", true}, {"api.example.org:443", false},
		{"any.example.org:1234", true}, {"node1.example.net", true},
		{"node12.example.net", false}, {"ignored.example", false},
	} {
		if got := m.MatchHostname(test.host); got != test.match {
			t.Errorf("MatchHostname(%q)=%v, want %v", test.host, got, test.match)
		}
	}
	if !(&Module{Hostnames: []string{"*", "-excluded.example"}}).MatchHostname("excluded.example") {
		t.Fatal("hostname matching must respect the first match")
	}
}

func TestModuleURLAndHeaderRewrites(t *testing.T) {
	m, err := Parse(`[URL Rewrite]
^https://old\.example/(.*) https://new.example/$1 302
^https://ad\.example/ _ reject
^http://plain\.example https://plain.example
[Header Rewrite]
http-request ^https://api\.example header-del X-Old
http-request ^https://api\.example header-add X-Test first
http-request ^https://api\.example header-add X-Test second
http-request ^https://api\.example header-replace X-Present "new value"
http-request ^https://api\.example header-replace X-Absent ignored
http-response ^https://api\.example header-replace-regex X-Version "v(\d+)" "release-$1"
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.URLRewrites) != 3 || len(m.HeaderRewrites) != 6 {
		t.Fatalf("unexpected rewrites: %+v", m)
	}
	got, err := m.URLRewrites[0].Rewrite("https://old.example/path?q=1")
	if err != nil || got != "https://new.example/path?q=1" {
		t.Fatalf("rewrite=(%q,%v)", got, err)
	}
	if m.URLRewrites[2].Type != "header" {
		t.Fatal("wrong default URL Rewrite type")
	}
	headers := http.Header{"X-Old": {"remove"}, "X-Present": {"old"}, "X-Version": {"v1", "v2"}}
	for _, rule := range m.HeaderRewrites {
		if !rule.Match("https://api.example/path") {
			t.Fatal("header URL did not match")
		}
		if err := rule.Apply(headers); err != nil {
			t.Fatal(err)
		}
	}
	if headers.Get("X-Old") != "" || headers.Get("X-Absent") != "" || headers.Get("X-Present") != "new value" {
		t.Fatalf("wrong header update: %+v", headers)
	}
	if strings.Join(headers.Values("X-Test"), ",") != "first,second" || strings.Join(headers.Values("X-Version"), ",") != "release-1,release-2" {
		t.Fatalf("multi-value headers lost: %+v", headers)
	}
	for _, field := range []string{"Content-Length", "Transfer-Encoding"} {
		if _, err := Parse("[Header Rewrite]\n. header-del "+field, nil); err == nil {
			t.Fatalf("accepted framing rewrite %s", field)
		}
	}
}

func TestModuleLoadLocalAndDeduplicateScripts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.js"), []byte("$done({});"), 0600); err != nil {
		t.Fatal(err)
	}
	modulePath := filepath.Join(dir, "local.sgmodule")
	if err := os.WriteFile(modulePath, []byte("[Script]\na = type=http-request,pattern=.,script-path=main.js\nb = type=http-response,pattern=.,script-path=main.js"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"file:local.sgmodule", (&url.URL{Scheme: "file", Path: modulePath}).String()} {
		m, err := Load(context.Background(), source, nil, LoadOptions{BaseDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if m.Name != "local.sgmodule" || len(m.Scripts) != 2 || m.Scripts[0].Source != "$done({});" || m.Scripts[1].Source != "$done({});" {
			t.Fatalf("unexpected loaded module from %q: %+v", source, m)
		}
	}
}

func TestModuleLoadRejectsUnsafeAndFailedDownloads(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/local":
			fmt.Fprint(w, "[Script]\na = type=http-request,pattern=.,script-path=file:///etc/passwd")
		case "/http":
			fmt.Fprint(w, "[Script]\na = type=http-request,pattern=.,script-path=http://example.com/a.js")
		case "/redirect":
			http.Redirect(w, r, "http://example.com/module.sgmodule", http.StatusFound)
		case "/oversize":
			w.Header().Set("Content-Length", fmt.Sprint(MaxModuleBytes+1))
			w.WriteHeader(http.StatusOK)
		case "/missing-script":
			fmt.Fprint(w, "[Script]\na = type=http-request,pattern=.,script-path=missing.js")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for _, path := range []string{"/local", "/http", "/redirect", "/oversize", "/missing", "/missing-script"} {
		t.Run(path, func(t *testing.T) {
			if _, err := Load(context.Background(), server.URL+path, server.Client(), LoadOptions{}); err == nil {
				t.Fatal("accepted unsafe or unsuccessful download")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, server.URL, nil, LoadOptions{}); err == nil {
		t.Fatal("ignored cancellation")
	}
}
