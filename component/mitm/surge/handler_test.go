// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func testUpstream(dial mitm.DialContext) mitm.UpstreamPlanner {
	return func(*http.Request) (mitm.UpstreamPlan, error) {
		if dial == nil {
			return mitm.UpstreamPlan{}, errors.New("unexpected upstream request")
		}
		return mitm.UpstreamPlan{Key: "test", Dial: dial}, nil
	}
}

func testProxyEngine(t *testing.T, module, source string) *Engine {
	t.Helper()
	m, err := Parse(module, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Scripts {
		m.Scripts[i].Source = source
	}
	if len(m.Hostnames) == 0 {
		m.Hostnames = []string{"example.com"}
	}
	rt, err := NewRuntime(RuntimeOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &Engine{options: EngineOptions{BodyMemory: testBodyMemory, Modules: []*Module{m}, Runtime: rt, MaxBodySize: 1 << 20, ScriptTimeout: time.Second}, slots: make(chan struct{}, 2)}
}

func TestSurgeProxyRequestRewriteAndFirstMatch(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
first = type=http-request,pattern=^http://example.com/,requires-body=1,script-path=a.js
second = type=http-request,pattern=^http://example.com/,requires-body=1,script-path=b.js
`, `const headers=$request.headers; headers["X-Script"]="yes"; $done({headers, body:$request.body+"!"});`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "hello!" || r.Header.Get("X-Script") != "yes" || r.Host != "example.com" {
			t.Errorf("received body=%q headers=%v host=%s", body, r.Header, r.Host)
		}
		if r.ContentLength != 6 {
			t.Errorf("content length=%d", r.ContentLength)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	handler, close := proxyTestHost(t, engine).Handler("http", "example.com", 80, testUpstream(func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(upstream.URL, "http://"))
	}))
	defer close()
	req := httptest.NewRequest("POST", "http://example.com/test", strings.NewReader("hello"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
}

func TestSurgeProxySyntheticDoesNotDialAndChecksAuthority(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
mock = type=http-request,pattern=.,script-path=a.js
`, `$done({response:{status:201,headers:{"Content-Type":"application/json"},body:'{"ok":true}'}});`)
	handler, close := proxyTestHost(t, engine).Handler("https", "example.com", 443, testUpstream(func(context.Context, string, string) (net.Conn, error) {
		t.Error("synthetic response dialed upstream")
		return nil, nil
	}))
	defer close()
	for _, test := range []struct {
		host   string
		status int
	}{{"example.com", 201}, {"evil.example", 421}, {"example.com:8443", 421}} {
		req := httptest.NewRequest("GET", "https://"+test.host+"/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != test.status {
			t.Fatalf("host=%s code=%d", test.host, w.Code)
		}
	}
}

func TestSurgeProxyCompressedBinaryResponseAndTrailers(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
rewrite = type=http-response,pattern=.,requires-body=1,binary-body-mode=1,script-path=a.js
`, `if (!($response.body instanceof Uint8Array)) throw Error("expected bytes"); $done({body:new Uint8Array([...$response.body,255])});`)
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = z.Write([]byte{0, 1, 128})
	_ = z.Close()
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	response := &http.Response{Request: req, StatusCode: 200, Body: io.NopCloser(bytes.NewReader(compressed.Bytes())), ContentLength: int64(compressed.Len()), Header: http.Header{"Content-Encoding": {"gzip"}, "Etag": {"old"}}, Trailer: http.Header{"Grpc-Status": {"0"}}}
	if err := engine.processResponse(response, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if !bytes.Equal(body, []byte{0, 1, 128, 255}) {
		t.Fatalf("body=%v", body)
	}
	if response.Header.Get("Content-Encoding") != "" || response.Header.Get("Etag") != "" || response.ContentLength != -1 || response.Header.Get("Content-Length") != "" || response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("response=%+v", response)
	}
}

func TestSurgeProxyRejectsOversizedDecompressedBody(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
bounded = type=http-request,pattern=.,requires-body=1,max-size=16,script-path=a.js
`, `$done({});`)
	req := httptest.NewRequest("POST", "https://example.com/", strings.NewReader(strings.Repeat("x", 17)))
	if _, err := engine.processRequest(&plugin.Exchange{Request: req, Client: http.DefaultClient, SetReadDeadline: http.NewResponseController(httptest.NewRecorder()).SetReadDeadline}); err != membuffer.ErrTooLarge {
		t.Fatalf("error=%v", err)
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = z.Write([]byte(strings.Repeat("x", 100)))
	_ = z.Close()
	view, err := membuffer.Read(bytes.NewReader(compressed.Bytes()), 1024, testBodyMemory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBodyView(view, "gzip", 16, testBodyMemory); err != membuffer.ErrTooLarge {
		t.Fatalf("decode error=%v", err)
	}
}

func TestSurgeProxyStreamsOversizedResponse(t *testing.T) {
	for _, encoding := range []string{"", "gzip"} {
		t.Run(encoding, func(t *testing.T) {
			engine := testProxyEngine(t, `[Script]
bounded = type=http-response,pattern=.,requires-body=1,max-size=64,script-path=a.js
`, `$done({body:"must not replace oversized response"});`)
			var capture proxyTraceCapture
			engine.options.Logger = capture.logger()
			raw := encodeBodyRewriteTest(t, []byte(strings.Repeat("x", 1024)), encoding)
			response := bodyRewriteResponse(raw, encoding)
			response.ContentLength = -1
			response.Header.Del("Content-Length")
			response.Trailer = http.Header{"X-Final": {"keep"}}
			headers := response.Header.Clone()
			tracked := &bodyRewriteTrackedReader{Reader: bytes.NewReader(raw)}
			response.Body = tracked
			if err := engine.processResponse(response, http.DefaultClient); err != nil {
				t.Fatal(err)
			}
			if tracked.closed || tracked.readBytes > 65 {
				t.Fatalf("response was closed or read beyond buffer limit: %+v", tracked)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || !bytes.Equal(body, raw) || !tracked.closed || !reflect.DeepEqual(response.Header, headers) || response.Trailer.Get("X-Final") != "keep" || response.ContentLength != -1 {
				t.Fatalf("fallback changed response or lost body ownership: response=%+v err=%v closed=%t", response, err, tracked.closed)
			}
			events := capture.trace
			var skipped bool
			for _, event := range events {
				if event["event"] == "script_start" {
					t.Fatal("oversized response executed its script")
				}
				skipped = skipped || event["outcome"] == "skipped" && event["reason"] == "body_limit"
			}
			if !skipped {
				t.Fatalf("missing skip diagnostic: %v", events)
			}
		})
	}
}

func TestSurgeProxyPreservesUnbufferedStreaming(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
headers = type=http-response,pattern=.,script-path=a.js
`, `$done({headers:{"X-Header":"done"}});`)
	body := &unreadBody{}
	response := &http.Response{Request: httptest.NewRequest("GET", "https://example.com/", nil), StatusCode: 200, Body: body, Header: make(http.Header)}
	if err := engine.processResponse(response, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if response.Body != body || body.read {
		t.Fatal("header-only script read the streaming body")
	}
}

func TestSurgeProxyAbort(t *testing.T) {
	engine := testProxyEngine(t, `[Script]
abort = type=http-request,pattern=.,script-path=a.js
`, `$done({abort:true});`)
	handler, close := proxyTestHost(t, engine).Handler("https", "example.com", 443, testUpstream(nil))
	defer close()
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Errorf("abort=%v", got)
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://example.com/", nil))
}

func TestSurgeProxyLimitsBufferingConcurrency(t *testing.T) {
	for _, test := range []struct {
		name, option string
		global       time.Duration
	}{
		{"inherit", "", 10 * time.Millisecond},
		{"override", ",timeout=0.01", time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := testProxyEngine(t, "[Script]\nbounded = type=http-request,pattern=.,requires-body=1,script-path=a.js"+test.option, `$done({});`)
			engine.slots = make(chan struct{}, 1)
			engine.slots <- struct{}{}
			engine.options.ScriptTimeout = test.global
			body := &unreadBody{}
			req := httptest.NewRequest("POST", "https://example.com/", nil)
			req.Body = body
			start := time.Now()
			if _, err := engine.processRequest(&plugin.Exchange{Request: req, Client: http.DefaultClient, SetReadDeadline: http.NewResponseController(httptest.NewRecorder()).SetReadDeadline}); err != context.DeadlineExceeded {
				t.Fatalf("error=%v", err)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("waiting for script capacity exceeded its budget: %v", elapsed)
			}
			if body.read {
				t.Error("body buffered before acquiring script capacity")
			}
		})
	}
}

type unreadBody struct{ read bool }

func (b *unreadBody) Read([]byte) (int, error) { b.read = true; return 0, io.EOF }
func (b *unreadBody) Close() error             { return nil }

func proxyTestHost(t *testing.T, engine *Engine) *mitm.Host {
	t.Helper()
	host, err := mitm.New(mitm.Options{Authority: &mitmca.Authority{}}, mitm.Instance{ID: "surge", Type: "surge", Plugin: engine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host
}
