// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func encodeRuntimeHTTPBody(t *testing.T, body []byte, encodings ...string) []byte {
	t.Helper()
	for _, encoding := range encodings {
		var encoded bytes.Buffer
		var writer io.WriteCloser
		switch encoding {
		case "gzip":
			writer = gzip.NewWriter(&encoded)
		case "deflate":
			writer = zlib.NewWriter(&encoded)
		case "raw-deflate":
			var err error
			writer, err = flate.NewWriter(&encoded, flate.DefaultCompression)
			if err != nil {
				t.Fatal(err)
			}
		case "br":
			writer = brotli.NewWriter(&encoded)
		default:
			t.Fatalf("unknown test encoding %q", encoding)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		body = encoded.Bytes()
	}
	return body
}

func TestRuntimeHTTPCompressedResponses(t *testing.T) {
	for _, test := range []struct {
		name, encoding string
		layers         []string
	}{
		{name: "uncompressed"},
		{name: "identity", encoding: "identity"},
		{name: "gzip", encoding: "gzip", layers: []string{"gzip"}},
		{name: "deflate", encoding: "deflate", layers: []string{"deflate"}},
		{name: "raw-deflate", encoding: "deflate", layers: []string{"raw-deflate"}},
		{name: "brotli", encoding: "br", layers: []string{"br"}},
		{name: "stacked", encoding: " GZip , BR ", layers: []string{"gzip", "br"}},
	} {
		for _, binary := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/binary=%t", test.name, binary), func(t *testing.T) {
				plain := []byte(`{"code":0,"data":{"amount":"0.15","msg":"签到成功！"}}`)
				if binary {
					plain = []byte{0, 255, 128, 1}
				}
				encoded := encodeRuntimeHTTPBody(t, plain, test.layers...)
				_, trust, dial := integrationUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Accept-Encoding") != "gzip, deflate, br" || r.Method != "POST" {
						t.Errorf("request changed: %s %v", r.Method, r.Header)
					}
					// Multiple field lines must be decoded in reverse application order.
					if test.encoding != "" {
						for encoding := range strings.SplitSeq(test.encoding, ",") {
							w.Header().Add("Content-Encoding", strings.TrimSpace(encoding))
						}
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
					w.Header().Set("X-Fixture", "keep")
					_, _ = w.Write(encoded)
				}))
				host, err := mitm.New(mitm.Options{UpstreamTLSConfig: trust})
				if err != nil {
					t.Fatal(err)
				}
				defer host.Close()
				client, closeClient := host.RoutedHTTPClient(testUpstream(dial))
				defer closeClient()
				r := testRuntime(t, RuntimeOptions{})
				result, err := r.Run(t.Context(), fmt.Sprintf(`
                  $httpClient.post({url:"https://example.com/sign", headers:{"Accept-Encoding":"gzip, deflate, br"}, body:"{}", "binary-mode":%t}, (error, response, data) => {
                    if (error) throw Error(error);
                    if (response.status !== 200 || response.headers["x-fixture"] !== "keep") throw Error("response metadata lost");
                    if (%t && ("content-encoding" in response.headers || "content-length" in response.headers)) throw Error("stale compressed headers");
                    if (%t) {
                      if (!(data instanceof Uint8Array)) throw Error("not binary");
                    } else if (JSON.parse(data).data.amount !== "0.15") throw Error("invalid JSON");
                    $done({body:data});
                  });
                `, binary, test.encoding != "", binary), Invocation{HTTPClient: client})
				if err != nil || result.Body == nil || !bytes.Equal(result.Body.Bytes(), plain) {
					t.Fatalf("decoded response: result=%#v err=%v", result, err)
				}
			})
		}
	}
}

func TestRuntimeHTTPAlreadyDecodedAndEmptyResponses(t *testing.T) {
	for _, test := range []struct {
		name, method string
		status       int
	}{
		{"transport-gzip", "get", 200},
		{"head", "head", 200},
		{"no-content", "get", 204},
		{"not-modified", "get", 304},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := encodeRuntimeHTTPBody(t, []byte("decoded once"), "gzip")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(test.status)
				if r.Method != "HEAD" && test.status == 200 {
					_, _ = w.Write(encoded)
				}
			}))
			defer server.Close()
			client := server.Client()
			// The transport must not transparently decompress bodyless responses
			// in this test; only the first case exercises its automatic gzip path.
			if test.name != "transport-gzip" {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.DisableCompression = true
				defer transport.CloseIdleConnections()
				client = &http.Client{Transport: transport}
			}
			r := testRuntime(t, RuntimeOptions{})
			result, err := r.Run(t.Context(), fmt.Sprintf(`
              $httpClient.%s(%q, (error, response, data) => {
                if (error) throw Error(error);
                if (response.status !== %d) throw Error("wrong status");
                $done({body:data});
              });
            `, test.method, server.URL, test.status), Invocation{HTTPClient: client})
			want := ""
			if test.name == "transport-gzip" {
				want = "decoded once"
			}
			if err != nil || result.Body == nil || string(result.Body.Bytes()) != want {
				t.Fatalf("bodyless/already decoded result=%#v err=%v", result, err)
			}
		})
	}
}

func TestScriptHTTPDecodingErrorsReleaseMemory(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate", "br"} {
		valid := encodeRuntimeHTTPBody(t, bytes.Repeat([]byte("x"), 4096), encoding)
		for _, test := range []struct {
			name      string
			body      []byte
			maxBody   int64
			budget    int64
			wantError error
		}{
			{"truncated", valid[:len(valid)-1], 8192, 1 << 20, nil},
			{"wire-limit", valid, 8, 1 << 20, membuffer.ErrTooLarge},
			{"decoded-limit", valid, 128, 1 << 20, membuffer.ErrTooLarge},
			{"decoded-budget", valid, 8192, 750, membuffer.ErrBudgetExhausted},
		} {
			t.Run(encoding+"/"+test.name, func(t *testing.T) {
				body := &bodyRewriteTrackedReader{Reader: bytes.NewReader(test.body)}
				client := &http.Client{Transport: runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {encoding}}, Body: body}, nil
				})}
				budget := membuffer.NewBudget(test.budget)
				message, memory, err := scriptHTTP(t.Context(), client, `{"url":"https://example.com/","method":"GET"}`, test.maxBody, budget)
				memory.Close()
				if err == nil || test.wantError != nil && !errors.Is(err, test.wantError) || message != "" {
					t.Fatalf("error=%v want=%v message=%q", err, test.wantError, message)
				}
				if !body.closed || budget.Status().Used != 0 || budget.Status().Peak > test.budget {
					t.Fatalf("body closed=%t budget=%+v", body.closed, budget.Status())
				}
			})
		}
	}
}

func TestRuntimeHTTPDecodeFailureCallback(t *testing.T) {
	for _, encoding := range []string{"gzip", "unsupported", "gzip, br"} {
		t.Run(encoding, func(t *testing.T) {
			body := []byte("invalid gzip")
			if encoding == "gzip, br" {
				body = encodeRuntimeHTTPBody(t, body, "br")
			}
			client := &http.Client{Transport: runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {encoding}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			r := testRuntime(t, RuntimeOptions{})
			_, err := r.Run(t.Context(), `
              $httpClient.get("https://example.com/", (error, response, data) => {
                if (typeof error !== "string" || !error.includes("decode $httpClient response")) throw Error("missing decode error");
                if (response !== null || data !== null) throw Error("partial response escaped");
                $done();
              });
            `, Invocation{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Complete the wire read at the cancellation boundary. Returning EOF (rather
// than a network error) ensures response processing must check the context.
type runtimeHTTPEOFBody struct {
	io.Reader
	finish func()
	closed bool
}

func (b *runtimeHTTPEOFBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		b.finish()
	}
	return n, err
}

func (b *runtimeHTTPEOFBody) Close() error {
	b.closed = true
	return nil
}

func TestScriptHTTPContextAfterWireEOF(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "deflate", "br"} {
		var layers []string
		if encoding != "" {
			layers = []string{encoding}
		}
		encoded := encodeRuntimeHTTPBody(t, bytes.Repeat([]byte("x"), 16<<10), layers...)
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%t", encoding, deadline), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				body := &runtimeHTTPEOFBody{Reader: bytes.NewReader(encoded), finish: cancel}
				client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					if deadline {
						body.finish = func() { <-req.Context().Done() }
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {encoding}}, Body: body}, nil
				})}
				timeout, want := 0.0, context.Canceled
				if deadline {
					timeout, want = 0.01, context.DeadlineExceeded
				}
				budget := membuffer.NewBudget(1 << 20)
				message, memory, err := scriptHTTP(ctx, client, fmt.Sprintf(`{"url":"https://example.com/","method":"GET","timeout":%g}`, timeout), 32<<10, budget)
				memory.Close()
				if !errors.Is(err, want) || message != "" {
					t.Fatalf("expired request returned message=%q error=%v, want %v", message, err, want)
				}
				if !body.closed || budget.Status().Used != 0 {
					t.Fatalf("body closed=%t, budget=%+v", body.closed, budget.Status())
				}
			})
		}
	}
}

func TestRuntimeHTTPCompressedResponseTimeout(t *testing.T) {
	// A small wire response that expands enough to outlast the HTTP deadline.
	// The script has a longer budget so it can handle the request's error callback.
	encoded := encodeRuntimeHTTPBody(t, bytes.Repeat([]byte("x"), 16<<20), "gzip")
	body := &bodyRewriteTrackedReader{Reader: bytes.NewReader(encoded)}
	client := &http.Client{Transport: runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}}, Body: body}, nil
	})}
	r := testRuntime(t, RuntimeOptions{Timeout: 5 * time.Second})
	_, err := r.Run(t.Context(), `
      $httpClient.get({url:"https://example.com/", timeout:0.005, "binary-mode":true}, (error, response, data) => {
        if (typeof error !== "string" || !error.includes("context deadline exceeded")) throw Error("missing request timeout");
        if (response !== null || data !== null) throw Error("expired response escaped");
        $done();
      });
    `, Invocation{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if !body.closed || r.budget.Status().Used != 0 {
		t.Fatalf("body closed=%t, budget=%+v", body.closed, r.budget.Status())
	}
}
