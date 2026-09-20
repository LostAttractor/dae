// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

func tlsTraceEvents(t *testing.T, c *proxyTraceCapture) []map[string]string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, fields := range c.trace {
		if fields["event"] == "" || fields["connection_id"] == "" {
			t.Errorf("TLS trace lacks event or connection identity: %v", fields)
		}
		for _, private := range []string{"tls-query-private", "tls-fragment-private", "synthetic-body-private"} {
			if strings.Contains(fmt.Sprint(fields), private) {
				t.Errorf("TLS trace leaked request or response contents: %v", fields)
			}
		}
	}
	return append([]map[string]string(nil), c.trace...)
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

func TestProxyTLSLogHTTP1AndHTTP2RequestCorrelation(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", useHTTP2), func(t *testing.T) {
			engine, roots := integrationEngine(t, map[string]string{
				"http-request": `$done({response:{status:200,body:"synthetic-body-private"}})`,
			}, nil)
			capture := new(proxyTraceCapture)
			engine.options.Logger = capture.logger()
			var dials atomic.Int32
			client := integrationClient(t, engine, roots, func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected upstream dial")
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
			events := tlsTraceEvents(t, capture)

			begins, ends := proxyTLSLogEvents(events, "request_begin"), proxyTLSLogEvents(events, "script_end")
			if len(begins) != 2 || len(ends) != 2 {
				t.Fatalf("expected two requests and script completions: begins=%v ends=%v", begins, ends)
			}
			connectionID := begins[0]["connection_id"]
			requests := make(map[string]bool)
			for _, begin := range begins {
				id := begin["request_id"]
				if begin["connection_id"] != connectionID || id == "" || requests[id] || begin["method"] != "GET" || begin["host"] != "example.com" {
					t.Fatalf("request IDs were missing/reused or context was incorrect: %v", begins)
				}
				requests[id] = true
			}
			for _, end := range ends {
				if !requests[end["request_id"]] || end["connection_id"] != connectionID || end["outcome"] != "synthetic" || end["phase"] != "http-request" || end["script"] != "http-request" {
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
			capture := new(proxyTraceCapture)
			engine.options.Logger = capture.logger()
			var dials atomic.Int32
			client := integrationClient(t, engine, roots, func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected upstream dial")
			}, true)
			if response, err := client.Get("https://" + test.target + "/trace/failed"); err == nil {
				response.Body.Close()
				t.Fatal("client unexpectedly completed a rejected TLS handshake")
			}
			client.CloseIdleConnections()
			events := tlsTraceEvents(t, capture)

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
