// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

type surgeLogHook func(*log.Entry)

func (h surgeLogHook) Levels() []log.Level     { return log.AllLevels }
func (h surgeLogHook) Fire(e *log.Entry) error { h(e); return nil }

func testSurgeLogger(h surgeLogHook) *log.Entry {
	logger := log.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(log.TraceLevel)
	logger.AddHook(h)
	return log.NewEntry(logger)
}

type proxyTraceCapture struct {
	mu       sync.Mutex
	trace    []map[string]string
	warnings []string
}

func (c *proxyTraceCapture) logger() *log.Entry {
	return testSurgeLogger(func(e *log.Entry) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if e.Level == log.WarnLevel {
			c.warnings = append(c.warnings, e.Message)
		}
		if e.Level == log.TraceLevel {
			fields := make(map[string]string, len(e.Data))
			for key, value := range e.Data {
				fields[key] = fmt.Sprint(value)
			}
			c.trace = append(c.trace, fields)
		}
	})
}

func (c *proxyTraceCapture) events(t *testing.T) []map[string]string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var events []map[string]string
	for _, fields := range c.trace {
		line := fmt.Sprint(fields)
		for _, private := range []string{
			"query-private-value", "fragment-private-value", "request-body-private-value",
			"response-body-private-value", "header-private-value", "argument-private-value",
			"local-body-private-value", "rewrite-body-private-value", "X-Private-Header",
			"error-private-value", "path-private-value",
		} {
			if strings.Contains(line, private) {
				t.Errorf("trace leaked private request/script data %q: %s", private, line)
			}
		}
		if fields["request_id"] == "" || fields["method"] != http.MethodPost || fields["host"] != "example.test" {
			t.Errorf("trace lacks safe request context: %s", line)
		}
		for _, key := range []string{"url", "headers", "body"} {
			if value, ok := fields[key]; ok && value != "true" && value != "false" {
				t.Errorf("trace %s must report only presence, got %q: %s", key, value, line)
			}
		}
		events = append(events, fields)
	}
	if len(events) == 0 {
		t.Fatal("request produced no execution trace")
	}
	for _, event := range events {
		if event["request_id"] != events[0]["request_id"] {
			t.Errorf("request trace IDs do not correlate: %v", events)
		}
	}
	return events
}

func findProxyTraceEvent(t *testing.T, events []map[string]string, name string, required map[string]string) map[string]string {
	t.Helper()
	for _, event := range events {
		if event["event"] != name {
			continue
		}
		match := true
		for key, want := range required {
			if event[key] != want {
				match = false
				break
			}
		}
		if match {
			return event
		}
	}
	t.Fatalf("missing trace event %s %v in %v", name, required, events)
	return nil
}

// Exercise the real Handler and ReverseProxy with a local upstream.
func serveProxyTraceRequest(t *testing.T, engine *Engine) (*httptest.ResponseRecorder, int32) {
	t.Helper()
	var dialCount atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Private-Header", "header-private-value")
		_, _ = io.WriteString(w, `{"private":"response-body-private-value","value":1}`)
	}))
	defer upstream.Close()
	handler, closeTransport := proxyTestHost(t, engine).Handler("http", "example.test", 80, testUpstream(func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialCount.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}))
	defer closeTransport()
	request := httptest.NewRequest(http.MethodPost, "http://example.test/path-private-value?auth=query-private-value", strings.NewReader(`{"private":"request-body-private-value"}`))
	request.URL.Fragment = "fragment-private-value"
	request.Header.Set("X-Private-Header", "header-private-value")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response, dialCount.Load()
}

func TestProxyTraceScriptOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, phase, source, outcome string
		status                       int
		dials                        int32
	}{
		{"request success", "http-request", `$done({headers:{...$request.headers,"X-Rewritten":"yes"},body:$request.body+" rewritten"})`, "success", 200, 1},
		{"response success", "http-response", `$done({body:$response.body+" rewritten"})`, "success", 200, 1},
		{"request failure", "http-request", `throw Error("error-private-value")`, "failed", 200, 1},
		{"response failure", "http-response", `throw Error("error-private-value")`, "failed", 200, 1},
		{"invalid request headers", "http-request", `$done({headers:{"Bad Header":"header-private-value"}})`, "failed", 502, 0},
		{"invalid synthetic status", "http-request", `$done({response:{status:101}})`, "failed", 502, 0},
		{"invalid response status", "http-response", `$done({status:101})`, "failed", 502, 1},
		{"ignored request status", "http-request", `$done({status:201})`, "unchanged", 200, 1},
		{"ignored response fields", "http-response", `$done({url:"https://ignored.test/",response:{status:201}})`, "unchanged", 200, 1},
		{"unchanged", "http-request", `$done()`, "unchanged", 200, 1},
		{"synthetic", "http-request", `$done({response:{status:201,body:"local-body-private-value"}})`, "synthetic", 201, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := fmt.Sprintf("[Script]\ntrace-script = type=%s,pattern=.,requires-body=true,script-path=script.js,argument=argument-private-value\n", test.phase)
			engine := testProxyEngine(t, module+"\n[MITM]\nhostname=example.test\n", test.source)
			capture := new(proxyTraceCapture)
			engine.options.Logger = capture.logger()
			response, dials := serveProxyTraceRequest(t, engine)
			if response.Code != test.status || dials != test.dials {
				t.Fatalf("handler behavior changed: status=%d dials=%d body=%q", response.Code, dials, response.Body.String())
			}
			events := capture.events(t)
			findProxyTraceEvent(t, events, "request_begin", nil)
			identity := map[string]string{"script": "trace-script", "phase": test.phase}
			findProxyTraceEvent(t, events, "script_match", identity)
			findProxyTraceEvent(t, events, "script_start", identity)
			end := findProxyTraceEvent(t, events, "script_end", map[string]string{"script": "trace-script", "phase": test.phase, "outcome": test.outcome})
			if elapsed, err := strconv.ParseFloat(end["elapsed_ms"], 64); err != nil || elapsed < 0 {
				t.Errorf("script completion lacks elapsed time: %v", end)
			}
			if test.outcome == "failed" {
				if end["reason"] == "" || len(capture.warnings) == 0 {
					t.Errorf("failure lacks a trace reason or existing warning: %v", end)
				}
			}
			if test.dials != 0 {
				findProxyTraceEvent(t, events, "request_forward", nil)
				findProxyTraceEvent(t, events, "upstream_response", nil)
			} else if test.outcome == "synthetic" {
				findProxyTraceEvent(t, events, "response_local", nil)
			} else {
				findProxyTraceEvent(t, events, "request_failed", nil)
			}
		})
	}
}

func TestProxyTraceNoMatchingScripts(t *testing.T) {
	engine := testProxyEngine(t, "[MITM]\nhostname=example.test\n[Script]\nunmatched = type=http-request,pattern=^https://other.example/,script-path=script.js\n", `$done()`)
	capture := new(proxyTraceCapture)
	engine.options.Logger = capture.logger()
	response, dials := serveProxyTraceRequest(t, engine)
	if response.Code != http.StatusOK || dials != 1 {
		t.Fatalf("unmatched request was not forwarded: status=%d dials=%d", response.Code, dials)
	}
	events := capture.events(t)
	for _, phase := range []string{"http-request", "http-response"} {
		findProxyTraceEvent(t, events, "script_skip", map[string]string{"phase": phase, "reason": "no_match"})
	}
	for _, event := range events {
		if event["event"] == "script_start" || event["event"] == "script_end" {
			t.Errorf("unmatched script was reported as executed: %v", event)
		}
	}
}

func TestProxyTraceMapLocalAndBodyRewrite(t *testing.T) {
	for _, test := range []struct {
		name, module, matchEvent string
		dials                    int32
	}{
		{"map local", "#!name=trace-module\n[Map Local]\n. data-type=text data=local-body-private-value\n", "map_local_match", 0},
		{"body jq", "#!name=trace-module\n[Body Rewrite]\nhttp-response-jq . '.private=\"rewrite-body-private-value\"'\n", "body_rewrite_match", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := testProxyEngine(t, test.module+"\n[MITM]\nhostname=example.test\n", "")
			capture := new(proxyTraceCapture)
			engine.options.Logger = capture.logger()
			response, dials := serveProxyTraceRequest(t, engine)
			if response.Code != http.StatusOK || dials != test.dials {
				t.Fatalf("rewrite behavior changed: status=%d dials=%d", response.Code, dials)
			}
			events := capture.events(t)
			match := findProxyTraceEvent(t, events, test.matchEvent, nil)
			if match["module"] != "trace-module" || match["rule"] == "" {
				t.Errorf("rewrite trace lacks rule identity: %v", match)
			}
			if test.dials == 0 {
				findProxyTraceEvent(t, events, "response_local", nil)
			} else {
				findProxyTraceEvent(t, events, "body_rewrite_end", map[string]string{"outcome": "modified"})
			}
		})
	}
}

func TestRequestCancellationAndUpstreamErrorsDoNotWarn(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		engine := testProxyEngine(t, "[MITM]\nhostname=example.test\n[Script]\ntest=type=http-request,pattern=.,script-path=script.js\n", `$done()`)
		capture := new(proxyTraceCapture)
		engine.options.Logger = capture.logger()
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(ctx)
		handler := engine.Wrap(plugin.Flow{Host: "example.test", Port: 80}, func(*plugin.Exchange) (*http.Response, error) {
			return nil, errors.New("upstream unavailable")
		})
		_, _ = handler(&plugin.Exchange{Request: r})
		cancel()
		if len(capture.warnings) != 0 {
			t.Fatalf("canceled=%t: request failure emitted script warning: %v", canceled, capture.warnings)
		}
	}
}
