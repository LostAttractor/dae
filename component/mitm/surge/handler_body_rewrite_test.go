// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/daeuniverse/dae/component/plugin"
)

func bodyRewriteEngine(t *testing.T, limit int64, expressions ...string) *Engine {
	t.Helper()
	e := &Engine{options: EngineOptions{BodyMemory: plugin.BodyMemory, MaxBodySize: limit, ScriptTimeout: 200 * time.Millisecond}, slots: make(chan struct{}, 1)}
	for _, expression := range expressions {
		e.options.Modules = append(e.options.Modules, &Module{BodyRewrites: []BodyRewrite{testBodyRewrite(t, expression)}})
	}
	return e
}

func bodyRewriteResponse(data []byte, encoding string) *http.Response {
	return &http.Response{
		Request:    httptest.NewRequest(http.MethodGet, "https://example.test/data", nil),
		StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)),
		Header: http.Header{
			"Content-Type": {"application/json"}, "Content-Encoding": {encoding},
			"Content-Length": {strconv.Itoa(len(data))}, "Etag": {`"original"`},
			"Content-Md5": {"original digest"}, "Digest": {"original digest"},
		},
	}
}

func encodeBodyRewriteTest(t *testing.T, body []byte, encoding string) []byte {
	t.Helper()
	var encoded bytes.Buffer
	var writer io.WriteCloser
	switch encoding {
	case "gzip":
		writer = gzip.NewWriter(&encoded)
	case "br":
		writer = brotli.NewWriter(&encoded)
	default:
		return body
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func TestProxyBodyRewriteCompressedAndOrdered(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			e := bodyRewriteEngine(t, 1024, ".value += 1", ".value *= 2")
			response := bodyRewriteResponse(encodeBodyRewriteTest(t, []byte(`{"value":2}`), encoding), encoding)
			response.Trailer = http.Header{"Digest": {"stale"}, "X-Request-Id": {"retain-me"}}
			response.TransferEncoding = []string{"chunked"}
			if err := e.rewriteResponseBody(response); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			assertBodyRewriteJSON(t, body, `{"value":6}`)
			for _, header := range []string{"Content-Encoding", "Etag", "Content-Md5", "Digest"} {
				if response.Header.Get(header) != "" {
					t.Errorf("rewritten body retained stale %s", header)
				}
			}
			if response.Trailer.Get("Digest") != "" || response.Trailer.Get("X-Request-Id") != "retain-me" {
				t.Fatalf("rewriting lost business trailers or retained body metadata: %v", response.Trailer)
			}
			// The retained trailer requires unknown-length framing on HTTP/1.
			if response.ContentLength != -1 || response.Header.Get("Content-Length") != "" || len(response.TransferEncoding) != 0 {
				t.Fatalf("incorrect rewritten framing: %+v", response)
			}
		})
	}
}

func TestProxyBodyRewritePreservesOriginalOnFailure(t *testing.T) {
	for _, test := range []struct {
		name, expression, input string
		encoding                string
		limit                   int64
	}{
		{"invalid JSON", ".x=1", "not JSON", "gzip", 1024},
		{"empty output", "empty", ` {"keep":1} `, "gzip", 1024},
		{"evaluation failure", `.x | error("failed")`, `{"x":1}`, "br", 1024},
		{"output exceeds limit", `"x" * 100`, `{}`, "gzip", 64},
		{"decompressed exceeds limit", ".x=1", `{"x":"` + strings.Repeat("a", 1000) + `"}`, "gzip", 128},
		{"invalid compression", ".x=1", "invalid gzip bytes", "broken-gzip", 1024},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := encodeBodyRewriteTest(t, []byte(test.input), test.encoding)
			response := bodyRewriteResponse(raw, test.encoding)
			if test.encoding == "broken-gzip" {
				response.Header.Set("Content-Encoding", "gzip")
			}
			originalHeaders := response.Header.Clone()
			e := bodyRewriteEngine(t, test.limit, test.expression)
			if err := e.rewriteResponseBody(response); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || !bytes.Equal(body, raw) || !reflect.DeepEqual(response.Header, originalHeaders) || response.ContentLength != int64(len(raw)) {
				t.Fatalf("skipped rewrite changed response: body=%q headers=%v err=%v", body, response.Header, err)
			}
		})
	}
}

type bodyRewriteTrackedReader struct {
	io.Reader
	readBytes int
	closed    bool
}

func (r *bodyRewriteTrackedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.readBytes += n
	return n, err
}

func (r *bodyRewriteTrackedReader) Close() error { r.closed = true; return nil }

func TestProxyBodyRewriteStreamsOversizedOriginal(t *testing.T) {
	for _, knownLength := range []bool{true, false} {
		t.Run(fmt.Sprintf("known length=%t", knownLength), func(t *testing.T) {
			raw := []byte(`{"keep":"` + strings.Repeat("a", 1000) + `"}`)
			response := bodyRewriteResponse(raw, "")
			tracked := &bodyRewriteTrackedReader{Reader: bytes.NewReader(raw)}
			response.Body = tracked
			if !knownLength {
				response.ContentLength = -1
				response.Header.Del("Content-Length")
			}
			e := bodyRewriteEngine(t, 64, ".keep=null")
			if err := e.rewriteResponseBody(response); err != nil {
				t.Fatal(err)
			}
			if tracked.closed || tracked.readBytes > 65 || knownLength && tracked.readBytes != 0 {
				t.Fatalf("oversized response was consumed/closed: bytes=%d closed=%t", tracked.readBytes, tracked.closed)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || !bytes.Equal(body, raw) || !tracked.closed {
				t.Fatalf("streamed fallback lost original bytes or ownership: len=%d err=%v closed=%t", len(body), err, tracked.closed)
			}
		})
	}
}

func TestProxyBodyRewriteSkipsBodylessResponses(t *testing.T) {
	for _, status := range []int{101, 204, 304, 200} {
		response := bodyRewriteResponse(nil, "gzip")
		response.StatusCode = status
		if status == 200 {
			response.Request.Method = http.MethodHead
		}
		tracked := &bodyRewriteTrackedReader{Reader: strings.NewReader("must not be consumed")}
		response.Body = tracked
		e := bodyRewriteEngine(t, 64, ".x=1")
		if err := e.rewriteResponseBody(response); err != nil || tracked.readBytes != 0 || tracked.closed {
			t.Fatalf("bodyless status %d was consumed: bytes=%d closed=%t err=%v", status, tracked.readBytes, tracked.closed, err)
		}
	}
}

func TestProxyBodyRewriteDeadlinePreservesBodyAndReleasesSlot(t *testing.T) {
	e := bodyRewriteEngine(t, 1024, "def forever: forever; forever")
	e.options.ScriptTimeout = 20 * time.Millisecond
	raw := []byte(`{"keep":true}`)
	response := bodyRewriteResponse(raw, "")
	start := time.Now()
	if err := e.rewriteResponseBody(response); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("jq did not stop at deadline: %v", elapsed)
	}
	body, _ := io.ReadAll(response.Body)
	if !bytes.Equal(body, raw) || len(e.slots) != 0 {
		t.Fatalf("deadline lost original body or execution slot: body=%q slots=%d", body, len(e.slots))
	}
	// Contention must expire without consuming the response body.
	e.slots <- struct{}{}
	tracked := &bodyRewriteTrackedReader{Reader: bytes.NewReader(raw)}
	response.Body = tracked
	if err := e.rewriteResponseBody(response); err != nil || tracked.readBytes != 0 || tracked.closed {
		t.Fatalf("waiting for a slot consumed body: %v", err)
	}
	<-e.slots
}

func TestBodyRewriteCompiledFilterConcurrentUse(t *testing.T) {
	rule := testBodyRewrite(t, ".value += 1")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := rule.Apply(context.Background(), []byte(fmt.Sprintf(`{"value":%d}`, i)), 64, plugin.BodyMemory)
			defer body.Close()
			if err != nil || string(body.Bytes()) != fmt.Sprintf(`{"value":%d}`, i+1) {
				t.Errorf("shared compiled jq result: %v %v", body, err)
			}
		}()
	}
	wg.Wait()
}
