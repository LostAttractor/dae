// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

type failedRequestBody struct{ err error }

func (b failedRequestBody) Read([]byte) (int, error) { return 0, b.err }
func (failedRequestBody) Close() error               { return nil }

func TestZeroLengthRequestTrailerFraming(t *testing.T) {
	for _, kind := range []string{"empty", "late_trailer", "read_error", "unexpected_data"} {
		t.Run(kind, func(t *testing.T) {
			h := testHost(t, Options{})
			r := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
			r.ContentLength = 0
			r.Header.Set("Content-Length", "0")
			r.Body = &eofCallbackBody{Reader: strings.NewReader(""), eof: func() {
				if kind == "late_trailer" {
					// Like HTTP/3, replace the server's map at EOF.
					r.Trailer = http.Header{"X-Checksum": {"empty"}}
				}
			}}
			switch kind {
			case "read_error":
				r.Body = failedRequestBody{err: errors.New("stream reset")}
			case "unexpected_data":
				r.Body = io.NopCloser(strings.NewReader("not empty"))
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, in *http.Request) {
				body, err := io.ReadAll(in.Body)
				if err != nil || len(body) != 0 {
					t.Errorf("upstream body=%q, read=%v", body, err)
				}
				if kind == "late_trailer" {
					if in.ContentLength != -1 || in.Trailer.Get("X-Checksum") != "empty" {
						t.Errorf("upstream lost trailers: length=%d trailers=%v", in.ContentLength, in.Trailer)
					}
				} else if in.ContentLength != 0 || in.Header.Get("Content-Length") != "0" {
					t.Errorf("upstream lost empty framing: length=%d headers=%v", in.ContentLength, in.Header)
				}
				io.WriteString(w, "ok")
			}))
			defer upstream.Close()
			called := false
			handler := h.handlerForFlow("https", plugin.Flow{Host: "example.com", Port: 443}, roundTripFunc(func(out *http.Request) (*http.Response, error) {
				called = true
				out.URL.Scheme = "http"
				out.URL.Host = upstream.Listener.Addr().String()
				return upstream.Client().Transport.RoundTrip(out)
			}), http.DefaultClient)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			wantCalled := kind == "empty" || kind == "late_trailer"
			if called != wantCalled || (wantCalled && w.Code != http.StatusOK) || (!wantCalled && w.Code != http.StatusBadGateway) {
				t.Fatalf("forwarded=%t status=%d", called, w.Code)
			}
		})
	}
}

func TestRequestTrailersThroughBufferedMiddlewareAndReplay(t *testing.T) {
	for _, mode := range []string{"snapshot", "drained"} {
		t.Run(mode, func(t *testing.T) { testRequestTrailerRewrite(t, mode == "snapshot") })
	}
}

func testRequestTrailerRewrite(t *testing.T, snapshot bool) {
	payload := ""
	if snapshot {
		payload = "upload"
	}
	p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}},
		wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
			return func(e *plugin.Exchange) (*http.Response, error) {
				if snapshot {
					view, err := plugin.SnapshotBody(&e.Request.Body, 1024, bodyMemory)
					if err != nil {
						return nil, err
					}
					defer view.Close()
				} else if _, err := io.Copy(io.Discard, e.Request.Body); err != nil {
					return nil, err
				}
				if e.Request.Trailer.Get("X-Checksum") != "original" {
					t.Errorf("middleware lost decoded trailers: %v", e.Request.Trailer)
				}
				// An intentional middleware rewrite must survive replay too.
				e.Request.Trailer.Set("X-Checksum", "rewritten")
				return next(e)
			}
		}}
	ca, _ := http3TestAuthority(t)
	h := testHost(t, Options{Authority: ca}, Instance{Plugin: p})
	forwarded := false
	handler := h.handlerForFlow("https", plugin.Flow{Host: "example.com", Port: 443}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		forwarded = true
		for attempt := range 2 {
			if attempt != 0 {
				var err error
				r.Body, err = r.GetBody()
				if err != nil {
					return nil, err
				}
			}
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || string(body) != payload || r.Trailer.Get("X-Checksum") != "rewritten" {
				t.Errorf("attempt %d: body=%q trailers=%v read=%v", attempt, body, r.Trailer, err)
			}
		}
		return response("ok"), nil
	}), http.DefaultClient)
	r := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
	r.ContentLength = -1
	r.Body = &eofCallbackBody{Reader: strings.NewReader(payload), eof: func() {
		// HTTP/3 replaces the request's map, including previously unannounced keys.
		r.Trailer = http.Header{"X-Checksum": {"original"}}
	}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if !forwarded || w.Code != 200 {
		t.Fatalf("buffered forwarding: called=%t status=%d", forwarded, w.Code)
	}
}
