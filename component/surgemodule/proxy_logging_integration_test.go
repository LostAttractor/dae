// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type proxyTLSLogCapture struct {
	mu      sync.Mutex
	lines   []string
	ended   chan struct{}
	endOnce sync.Once
}

func newProxyTLSLogCapture() *proxyTLSLogCapture {
	return &proxyTLSLogCapture{ended: make(chan struct{})}
}

func (c *proxyTLSLogCapture) trace(line string) {
	c.mu.Lock()
	c.lines = append(c.lines, line)
	c.mu.Unlock()
	if strings.HasPrefix(line, "surge event=mitm_end ") {
		c.endOnce.Do(func() { close(c.ended) })
	}
}

func (c *proxyTLSLogCapture) waitForEnd(t *testing.T) []map[string]string {
	t.Helper()
	select {
	case <-c.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("MITM connection did not emit its completion event")
	}
	c.mu.Lock()
	lines := append([]string(nil), c.lines...)
	c.mu.Unlock()
	events := make([]map[string]string, 0, len(lines))
	for _, line := range lines {
		fields := make(map[string]string)
		for _, match := range proxyTraceField.FindAllStringSubmatch(line, -1) {
			value := match[2]
			if strings.HasPrefix(value, `"`) {
				var err error
				value, err = strconv.Unquote(value)
				if err != nil {
					t.Fatalf("invalid quoted TLS trace field: %s", line)
				}
			}
			fields[match[1]] = value
		}
		if fields["event"] == "" || fields["connection_id"] == "" {
			t.Errorf("TLS trace lacks event or connection identity: %s", line)
		}
		for _, private := range []string{"tls-query-private", "tls-fragment-private", "synthetic-body-private"} {
			if strings.Contains(line, private) {
				t.Errorf("TLS trace leaked request or response contents: %s", line)
			}
		}
		events = append(events, fields)
	}
	return events
}

func proxyTLSLogEvents(events []map[string]string, name string) []map[string]string {
	var selected []map[string]string
	for _, event := range events {
		if event["event"] == name {
			selected = append(selected, event)
		}
	}
	return selected
}

func assertProxyTLSConnectionIdentity(t *testing.T, events []map[string]string, outcome string) string {
	t.Helper()
	starts, ends := proxyTLSLogEvents(events, "mitm_start"), proxyTLSLogEvents(events, "mitm_end")
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("expected one connection lifecycle, got starts=%v ends=%v", starts, ends)
	}
	id := starts[0]["connection_id"]
	if id == "" || ends[0]["outcome"] != outcome {
		t.Fatalf("incorrect connection lifecycle identity or outcome: %v", events)
	}
	for _, event := range events {
		if event["connection_id"] != id {
			t.Errorf("event escaped its connection identity %s: %v", id, event)
		}
	}
	return id
}

func TestProxyTLSLogHTTP1AndHTTP2RequestCorrelation(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", useHTTP2), func(t *testing.T) {
			engine, roots := integrationEngine(t, map[string]string{
				"http-request": `$done({response:{status:200,body:"synthetic-body-private"}})`,
			}, nil)
			capture := newProxyTLSLogCapture()
			engine.options.Trace = capture.trace
			var dials atomic.Int32
			client := integrationClient(t, engine, roots, func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("synthetic request must not dial upstream")
			}, useHTTP2)
			for _, path := range []string{"/trace/first", "/trace/second"} {
				response, err := client.Get("https://example.com" + path + "?token=tls-query-private#tls-fragment-private")
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				wantVersion := 1
				if useHTTP2 {
					wantVersion = 2
				}
				if err != nil || response.StatusCode != 200 || string(body) != "synthetic-body-private" || response.ProtoMajor != wantVersion {
					t.Fatalf("synthetic TLS response: status=%d proto=%s body=%q err=%v", response.StatusCode, response.Proto, body, err)
				}
			}
			client.CloseIdleConnections()
			events := capture.waitForEnd(t)
			assertProxyTLSConnectionIdentity(t, events, "closed")
			ready := proxyTLSLogEvents(events, "tls_ready")
			if len(ready) != 1 || useHTTP2 && ready[0]["protocol"] != "h2" {
				t.Fatalf("TLS readiness was not logged correctly: %v", ready)
			}
			begins, ends := proxyTLSLogEvents(events, "request_begin"), proxyTLSLogEvents(events, "script_end")
			if len(begins) != 2 || len(ends) != 2 {
				t.Fatalf("expected two requests and script completions: begins=%v ends=%v", begins, ends)
			}
			requests := make(map[string]string)
			for _, begin := range begins {
				id := begin["request_id"]
				if id == "" || requests[id] != "" || begin["method"] != "GET" || begin["host"] != "example.com" {
					t.Fatalf("request IDs were missing/reused or context was incorrect: %v", begins)
				}
				requests[id] = begin["path"]
			}
			for _, end := range ends {
				path := requests[end["request_id"]]
				if path == "" || end["path"] != path || end["outcome"] != "synthetic" || end["phase"] != "http-request" || end["script"] != "http-request" {
					t.Errorf("script completion does not correlate with its request: %v", end)
				}
				delete(requests, end["request_id"])
			}
			if len(requests) != 0 || dials.Load() != 0 {
				t.Fatalf("missing script completion or unexpected upstream work: requests=%v dials=%d", requests, dials.Load())
			}
		})
	}
}

func TestProxyTLSLogHandshakeFailures(t *testing.T) {
	for _, test := range []struct {
		name, target string
		trustCA      bool
	}{
		{name: "client does not trust CA", target: "example.com"},
		{name: "SNI differs from routed host", target: "other.example", trustCA: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, roots := integrationEngine(t, map[string]string{
				"http-request": `$done({response:{body:"must not execute"}})`,
			}, nil)
			if !test.trustCA {
				roots = x509.NewCertPool()
			}
			capture := newProxyTLSLogCapture()
			engine.options.Trace = capture.trace
			var dials atomic.Int32
			client := integrationClient(t, engine, roots, func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("failed TLS must not reach upstream")
			}, true)
			if response, err := client.Get("https://" + test.target + "/trace/failed"); err == nil {
				response.Body.Close()
				t.Fatal("client unexpectedly completed a rejected TLS handshake")
			}
			client.CloseIdleConnections()
			events := capture.waitForEnd(t)
			assertProxyTLSConnectionIdentity(t, events, "failed")
			failures := proxyTLSLogEvents(events, "tls_handshake_failed")
			if len(failures) != 1 || failures[0]["reason"] == "" {
				t.Fatalf("missing handshake failure classification: %v", failures)
			}
			for _, forbidden := range []string{"tls_ready", "request_begin", "script_start", "script_end"} {
				if found := proxyTLSLogEvents(events, forbidden); len(found) != 0 {
					t.Errorf("failed TLS was logged as ready or executing requests: %v", found)
				}
			}
			if dials.Load() != 0 {
				t.Errorf("failed TLS dialed upstream %d times", dials.Load())
			}
		})
	}
}
