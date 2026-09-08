// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	log "github.com/sirupsen/logrus"
)

func TestBodyMemoryPressureForwardsOriginalRequestAndResponse(t *testing.T) {
	for _, phase := range []string{"http-request", "http-response"} {
		for _, limit := range []int64{500, 750, 4096} {
			t.Run(fmt.Sprintf("%s/%d", phase, limit), func(t *testing.T) {
				e := testProxyEngine(t, "[Script]\nedit = type="+phase+",pattern=.,requires-body=1,script-path=x.js", `$done({headers:{"X-Edited":"yes"},body:"edited"})`)
				e.options.MaxBodySize = 1024
				budget := membuffer.NewBudget(limit)
				e.options.BodyMemory = budget
				var logs []string
				e.options.Logger = testSurgeLogger(func(entry *log.Entry) {
					logs = append(logs, fmt.Sprint(entry.Data["error"]))
				})
				req := httptest.NewRequest("POST", "https://example.com/", strings.NewReader("original"))
				exchange := &plugin.Exchange{Request: req, Client: http.DefaultClient}
				defer func() { _ = req.Body.Close() }()
				var body io.ReadCloser
				var header http.Header
				if phase == "http-request" {
					if _, err := e.processRequest(exchange); err != nil {
						t.Fatal(err)
					}
					body, header = req.Body, req.Header
				} else {
					resp := bodyRewriteResponse([]byte("original"), "")
					if err := e.processResponse(resp, http.DefaultClient); err != nil {
						t.Fatal(err)
					}
					body, header = resp.Body, resp.Header
				}
				got, err := io.ReadAll(body)
				_ = body.Close()
				if err != nil {
					t.Fatal(err)
				}
				want := "original"
				if limit == 4096 {
					want = "edited"
				}
				if string(got) != want {
					t.Fatalf("body=%q want=%q", got, want)
				}
				if want == "original" && (header.Get("X-Edited") != "" || !strings.Contains(strings.Join(logs, "\n"), "memory budget exhausted")) {
					t.Fatalf("partial rewrite or missing diagnostics: %v %v", header, logs)
				}
				if budget.Status().Used != 0 || budget.Status().Peak > limit {
					t.Fatal(budget.Status())
				}
			})
		}
	}
}

func TestBodyMemoryPressurePreservesCompressedAndJQResponse(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			budget := membuffer.NewBudget(750)
			e := bodyRewriteEngine(t, 1024, ".value += 1")
			e.options.BodyMemory = budget
			original := encodeBodyRewriteTest(t, []byte(`{"value":2}`), encoding)
			resp := bodyRewriteResponse(original, encoding)
			if err := e.rewriteResponseBody(resp); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || string(got) != string(original) || resp.Header.Get("Etag") != `"original"` || resp.Header.Get("Content-Encoding") != encoding {
				t.Fatalf("fallback changed response: %q %v %v", got, err, resp.Header)
			}
			if budget.Status().Used != 0 || budget.Status().Denied == 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}

func TestScriptHTTPMemoryReleasedAfterDispatchAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello") }))
	defer server.Close()
	r, err := NewRuntime(RuntimeOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, wait := range []bool{true, false} {
		budget := membuffer.NewBudget(1 << 20)
		source := fmt.Sprintf(`$httpClient.get(%q, (error, response, data) => { if(error) throw Error(error); $done({body:data}); });`, server.URL)
		if !wait {
			source += `$done({});`
		}
		result, err := r.Run(context.Background(), source, Invocation{BodyMemory: budget, BodyLimit: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if wait && (result.Body == nil || string(result.Body.Bytes()) != "hello") {
			t.Fatal("lost HTTP event")
		}
		result.Close()
		if budget.Status().Used != 0 {
			t.Fatal(budget.Status())
		}
	}
}

func TestScriptResultMemoryReleasedOnFailure(t *testing.T) {
	r, err := NewRuntime(RuntimeOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		`$done({body:"allocated"}); throw Error("after done");`,
		`$done({body:"allocated", response:{body:"nested", status:999}});`,
		`$done({body:"x".repeat(2048)});`,
	} {
		budget := membuffer.NewBudget(4096)
		result, err := r.Run(context.Background(), source, Invocation{BodyMemory: budget, BodyLimit: 1024})
		if err == nil || result != nil {
			t.Fatalf("failure returned %v, %v", result, err)
		}
		if used := budget.Status().Used; used != 0 {
			t.Fatalf("failed invocation retained %d bytes", used)
		}
	}
}
