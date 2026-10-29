// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"strconv"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestResponseTakeHTTPDiscardsForbiddenBody(t *testing.T) {
	for _, tt := range []struct {
		name, method string
		status       int
		length, want int64
	}{
		{"head", http.MethodHead, http.StatusOK, 7, 7},
		{"head-unknown", http.MethodHead, http.StatusOK, -1, -1},
		{"head-empty", http.MethodHead, http.StatusOK, 0, 0},
		{"head-no-content", http.MethodHead, http.StatusNoContent, 7, 0},
		{"head-reset-content", http.MethodHead, http.StatusResetContent, 7, 0},
		{"head-reset-content-unknown", http.MethodHead, http.StatusResetContent, -1, 0},
		{"head-not-modified", http.MethodHead, http.StatusNotModified, 7, 7},
		{"no-content", http.MethodGet, http.StatusNoContent, 7, 0},
		{"reset-content", http.MethodGet, http.StatusResetContent, 7, 0},
		{"reset-content-unknown", http.MethodGet, http.StatusResetContent, -1, 0},
		{"reset-content-empty", http.MethodGet, http.StatusResetContent, 0, 0},
		{"not-modified", http.MethodGet, http.StatusNotModified, 7, 7},
		{"not-modified-unknown", http.MethodGet, http.StatusNotModified, -1, -1},
		{"informational", http.MethodGet, http.StatusEarlyHints, 7, 0},
		{"no-request", "", http.StatusNoContent, 7, 0},
		{"reset-content-no-request", "", http.StatusResetContent, 7, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := &countedBody{Reader: strings.NewReader("payload")}
			raw := &http.Response{
				StatusCode: tt.status, Body: source, ContentLength: tt.length,
				Header: http.Header{
					"Content-Length": {"999"}, "Transfer-Encoding": {"chunked"}, "Trailer": {"X-Final"},
					http.TrailerPrefix + "X-Late": {"unused"},
					"Etag":                        {`"original"`}, "Content-Encoding": {"gzip"}, "Repr-Digest": {"representation"},
				},
				TransferEncoding: []string{"chunked"}, Trailer: http.Header{"X-Final": {"unused"}},
			}
			if tt.method != "" {
				raw.Request = httptest.NewRequest(tt.method, "https://example.com/", nil)
			}
			response := NewResponse(raw, nil)
			defer response.Close()
			wire, _, err := response.TakeHTTP()
			if err != nil {
				t.Fatal(err)
			}
			if wire.Body != http.NoBody || source.reads != 0 || source.closes != 1 {
				t.Fatalf("body was not discarded without reading: body=%T reads=%d closes=%d", wire.Body, source.reads, source.closes)
			}
			if len(wire.Trailer) != 0 || len(wire.TransferEncoding) != 0 || wire.Header.Get("Trailer") != "" || wire.Header.Get("Transfer-Encoding") != "" || wire.Header.Get(http.TrailerPrefix+"X-Late") != "" {
				t.Fatal("bodyless response retained trailers or transfer framing", wire)
			}
			wantHeader := ""
			if tt.want >= 0 && tt.status >= 200 && tt.status != http.StatusNoContent {
				wantHeader = strconv.FormatInt(tt.want, 10)
			}
			if wire.ContentLength != tt.want || wire.Header.Get("Content-Length") != wantHeader {
				t.Fatalf("length=%d header=%q, want length=%d header=%q", wire.ContentLength, wire.Header.Get("Content-Length"), tt.want, wantHeader)
			}
			if wire.Header.Get("Etag") != `"original"` || wire.Header.Get("Content-Encoding") != "gzip" || wire.Header.Get("Repr-Digest") != "representation" {
				t.Fatal("discarding content removed representation metadata", wire.Header)
			}
			_ = wire.Body.Close()
			_ = response.Close()
			if source.closes != 1 {
				t.Fatal("source closed more than once", source.closes)
			}
			if _, _, err := response.TakeHTTP(); err == nil {
				t.Fatal("body ownership transferred more than once")
			}
		})
	}
}

func TestResponseTakeHTTPDoesNotSynthesize304Length(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			response := NewResponse(&http.Response{
				Request:    httptest.NewRequest(method, "https://example.com/", nil),
				StatusCode: http.StatusNotModified, Header: make(http.Header), Body: http.NoBody, ContentLength: 7,
			}, nil)
			wire, _, err := response.TakeHTTP()
			if err != nil {
				t.Fatal(err)
			}
			defer wire.Body.Close()
			if wire.ContentLength != 7 || len(wire.Header.Values("Content-Length")) != 0 {
				t.Fatal("304 acquired an undeclared content length", wire)
			}
		})
	}
}

func TestResponseTakeHTTPReleasesForbiddenBodyBudget(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusResetContent} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			budget := membuffer.NewBudget(4096)
			exchange := &Exchange{Request: NewRequest(httptest.NewRequest(http.MethodGet, "https://example.com/", nil), budget)}
			response := exchange.NewResponse(&http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("payload")), ContentLength: 7})
			defer response.Close()
			view, err := response.Body().Snapshot(64)
			if err != nil {
				t.Fatal(err)
			}
			view.Close()
			if budget.Status().Used == 0 {
				t.Fatal("snapshot did not reserve memory")
			}
			// Normalize the final status, not just the one supplied to NewResponse.
			response.Head.StatusCode = status
			wire, _, err := response.TakeHTTP()
			if err != nil {
				t.Fatal(err)
			}
			defer wire.Body.Close()
			if wire.Body != http.NoBody || budget.Status().Used != 0 {
				t.Fatal("discarded body retained its budget", budget.Status())
			}
		})
	}
}

type framingRoundTripper func(*http.Request) (*http.Response, error)

func (f framingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestResponseTakeHTTPBodylessReverseProxy(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(strconv.FormatBool(http2), func(t *testing.T) {
			proxy := &httputil.ReverseProxy{
				Director: func(*http.Request) {}, ErrorLog: log.New(io.Discard, "", 0),
				Transport: framingRoundTripper(func(request *http.Request) (*http.Response, error) {
					status, _ := strconv.Atoi(strings.TrimPrefix(request.URL.Path, "/"))
					exchange := &Exchange{Request: NewRequest(request, nil)}
					header := http.Header{http.TrailerPrefix + "X-Late": {"unused"}}
					if request.Method == http.MethodHead {
						header.Set("Content-Length", "7")
					}
					response := exchange.NewResponse(&http.Response{
						StatusCode: status, Header: header,
						Body: io.NopCloser(strings.NewReader("payload")), ContentLength: 7,
						Trailer: http.Header{"X-Final": {"unused"}},
					})
					wire, _, err := response.TakeHTTP()
					return wire, err
				}),
			}
			server := httptest.NewUnstartedServer(proxy)
			server.EnableHTTP2 = http2
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			requests := 0
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, status := range []int{http.StatusNoContent, http.StatusResetContent, http.StatusNotModified} {
					request, err := http.NewRequestWithContext(t.Context(), method, server.URL+"/"+strconv.Itoa(status), nil)
					if err != nil {
						t.Fatal(err)
					}
					reused := false
					request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
					response, err := client.Do(request)
					if err != nil {
						t.Fatalf("%s %d interrupted the client connection: %v", method, status, err)
					}
					data, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil || len(data) != 0 || response.StatusCode != status || len(response.Trailer) != 0 || len(response.TransferEncoding) != 0 {
						t.Fatalf("%s %d: body=%q response=%+v err=%v", method, status, data, response, err)
					}
					if status == http.StatusResetContent && (response.ContentLength != 0 || response.Header.Get("Content-Length") != "0") {
						t.Fatalf("205 is not framed as zero content: %+v", response)
					}
					if (response.ProtoMajor == 2) != http2 || requests > 0 && !reused {
						t.Fatalf("protocol=%s reused=%t after %d requests", response.Proto, reused, requests)
					}
					requests++
				}
			}
		})
	}
}
