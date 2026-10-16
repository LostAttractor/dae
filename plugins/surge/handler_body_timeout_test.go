// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

type delayedEOFBody struct {
	io.Reader
	finish func() error
}

func (b *delayedEOFBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		return n, b.finish()
	}
	return n, err
}

func (*delayedEOFBody) Close() error { return nil }

func TestSurgeSlowBodyDoesNotConsumeExecutionBudget(t *testing.T) {
	for _, phase := range []string{"http-request", "http-response", "body-rewrite"} {
		for _, outcome := range []string{"complete", "read-failure", "canceled"} {
			t.Run(phase+"/"+outcome, func(t *testing.T) {
				// The body takes longer than the execution budget before EOF.
				var e *Engine
				if phase == "body-rewrite" {
					e = bodyRewriteEngine(t, 1<<20, ".value = 2")
					e.options.Modules[0].BodyRewrites[0].Match(t.Context(), "https://example.test/data")
				} else {
					e = testProxyEngine(t, "[Script]\ntest=type="+phase+",pattern=.,requires-body=true,script-path=test.js", `$done({body:"rewritten"});`)
					e.matchScript(phase, httptest.NewRequest(http.MethodGet, "https://example.test/data", nil))
				}
				e.options.ScriptTimeout = 200 * time.Millisecond
				e.options.BodyMemory = membuffer.NewBudget(4 << 20)
				wire := encodeBodyRewriteTest(t, []byte(`{"value":1}`), "gzip")
				func() {
					parent, cancel := context.WithCancel(t.Context())
					defer cancel()
					response := bodyRewriteResponse(wire, "gzip")
					response.Request = response.Request.WithContext(parent)
					response.Body = &delayedEOFBody{Reader: bytes.NewReader(wire), finish: func() error {
						// Network time must not consume the later decoding/script budget.
						time.Sleep(300 * time.Millisecond)
						if outcome == "read-failure" {
							return context.DeadlineExceeded
						}
						if outcome == "canceled" {
							cancel()
						}
						return io.EOF
					}}
					var err error
					if phase == "http-request" {
						request := response.Request
						request.Body, request.Header, request.ContentLength = response.Body, response.Header, response.ContentLength
						var synthetic *http.Response
						synthetic, err = e.processRequest(&plugin.Exchange{Request: request})
						if synthetic != nil {
							t.Fatal("script unexpectedly synthesized a response")
						}
						response.Body, response.Header = request.Body, request.Header
					} else if phase == "body-rewrite" {
						err = e.rewriteResponseBody(response)
					} else {
						err = e.processResponse(response, nil)
					}
					defer response.Body.Close()
					switch outcome {
					case "complete":
						if err != nil {
							t.Fatalf("slow complete body failed: %v", err)
						}
						body, err := io.ReadAll(response.Body)
						want := "rewritten"
						if phase == "body-rewrite" {
							want = `{"value":2}`
						}
						if err != nil || string(body) != want || response.Header.Get("Content-Encoding") != "" {
							t.Fatalf("processing did not run after slow body: %q, %v, %v", body, response.Header, err)
						}
					case "read-failure":
						if !errors.Is(err, context.DeadlineExceeded) {
							t.Fatalf("read failure was swallowed: %v", err)
						}
					case "canceled":
						if err == nil {
							t.Fatal("request cancellation was swallowed")
						}
					}
				}()
				if used := e.options.BodyMemory.Status().Used; used != 0 {
					t.Fatalf("body budget leaked %d bytes", used)
				}
			})
		}
	}
}
