// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type proxyTraceCapture struct {
	mu              sync.Mutex
	trace, warnings []string
}

func (c *proxyTraceCapture) addTrace(message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trace = append(c.trace, message)
}

func (c *proxyTraceCapture) addWarning(message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warnings = append(c.warnings, message)
}

var proxyTraceField = regexp.MustCompile(`(?:^| )([a-z_]+)=("(?:\\.|[^"\\])*"|[^\s]+)`)

func (c *proxyTraceCapture) events(t *testing.T) []map[string]string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var events []map[string]string
	for _, line := range c.trace {
		if !strings.HasPrefix(line, "surge event=") {
			t.Fatalf("trace lacks its event prefix: %q", line)
		}
		for _, private := range []string{
			"query-private-value", "fragment-private-value", "request-body-private-value",
			"response-body-private-value", "header-private-value", "argument-private-value",
			"local-body-private-value", "rewrite-body-private-value", "X-Private-Header",
			"error-private-value",
		} {
			if strings.Contains(line, private) {
				t.Errorf("trace leaked private request/script data %q: %s", private, line)
			}
		}
		fields := make(map[string]string)
		for _, match := range proxyTraceField.FindAllStringSubmatch(line, -1) {
			value := match[2]
			if strings.HasPrefix(value, `"`) {
				var err error
				value, err = strconv.Unquote(value)
				if err != nil {
					t.Fatalf("invalid quoted trace field: %s", line)
				}
			}
			fields[match[1]] = value
		}
		if fields["request_id"] == "" || fields["method"] != http.MethodPost || fields["host"] != "example.test" || fields["path"] != "/visible/path" {
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
	handler, closeTransport := engine.Handler("http", "example.test", 80, func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialCount.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	})
	defer closeTransport()
	request := httptest.NewRequest(http.MethodPost, "http://example.test/visible/path?auth=query-private-value", strings.NewReader(`{"private":"request-body-private-value"}`))
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
			engine.options.Trace, engine.options.Log = capture.addTrace, capture.addWarning
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
	engine.options.Trace, engine.options.Log = capture.addTrace, capture.addWarning
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
			engine.options.Trace, engine.options.Log = capture.addTrace, capture.addWarning
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
