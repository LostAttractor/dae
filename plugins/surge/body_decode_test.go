// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestDecodeBodyViewEmptyCompatibility(t *testing.T) {
	for _, encoding := range []string{"gzip", "unknown", "gzip, br"} {
		t.Run(encoding, func(t *testing.T) {
			budget := membuffer.NewBudget(1)
			view, err := membuffer.Copy(nil, budget)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeBodyView(t.Context(), view, encoding, 1024)
			if err != nil || decoded != view {
				t.Fatalf("empty response: decoded=%v error=%v", decoded, err)
			}
			decoded.Close()
			if budget.Status().Used != 0 || budget.Status().Denied != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}

func TestHTTPContentEncodingMultipleFields(t *testing.T) {
	wire := encodeRuntimeHTTPBody(t, []byte(`{"value":2}`), "gzip", "br")
	for _, kind := range []string{"body-rewrite", "http-request", "http-response"} {
		t.Run(kind, func(t *testing.T) {
			var e *Engine
			if kind == "body-rewrite" {
				e = bodyRewriteEngine(t, 1024, ".value += 1")
			} else {
				e = testProxyEngine(t, "[Script]\nrewrite=type="+kind+",pattern=.,requires-body=1,script-path=a.js",
					`const body = JSON.parse((typeof $response === 'undefined' ? $request : $response).body); body.value++; $done({body: JSON.stringify(body)});`)
			}
			budget := membuffer.NewBudget(64 << 20)
			var source io.ReadCloser
			if kind == "http-request" {
				request := httptest.NewRequest("POST", "https://example.com/", bytes.NewReader(wire))
				request.Header["Content-Encoding"] = []string{"gzip", "br"}
				controlled := plugin.NewRequest(request, budget)
				defer controlled.Body().Close()
				if _, err := e.processRequest(&plugin.Exchange{Request: controlled}); err != nil {
					t.Fatal(err)
				}
				source = forwardTestRequest(t, controlled).Body
			} else {
				response := bodyRewriteResponse(wire, "")
				response.Header["Content-Encoding"] = []string{"gzip", "br"}
				controlled := plugin.NewResponse(response, budget)
				defer controlled.Close()
				var err error
				if kind == "body-rewrite" {
					err = e.rewriteResponseBody(controlled)
				} else {
					err = e.processResponse(controlled, nil)
				}
				if err != nil {
					t.Fatal(err)
				}
				source = takeTestResponse(t, controlled).Body
			}
			got, err := io.ReadAll(source)
			_ = source.Close()
			if err != nil {
				t.Fatal(err)
			}
			assertBodyRewriteJSON(t, got, `{"value":3}`)
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}

func TestDecodeBodyViewCanceledReleasesInput(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "deflate", "br", "gzip,br"} {
		t.Run(encoding, func(t *testing.T) {
			var layers []string
			if encoding != "" {
				layers = strings.Split(encoding, ",")
			}
			body := encodeRuntimeHTTPBody(t, []byte("decoded body"), layers...)
			budget := membuffer.NewBudget(1 << 20)
			view, err := membuffer.Copy(body, budget)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			decoded, err := decodeBodyView(ctx, view, encoding, 1024)
			decoded.Close()
			if !errors.Is(err, context.Canceled) || decoded != nil {
				t.Fatalf("canceled decode returned %v, %v", decoded, err)
			}
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}
