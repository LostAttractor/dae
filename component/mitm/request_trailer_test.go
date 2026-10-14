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
	"github.com/daeuniverse/dae/pkg/membuffer"
)

type failedRequestBody struct{ err error }

func (b failedRequestBody) Read([]byte) (int, error)  { return 0, b.err }
func (failedRequestBody) Close() error                { return nil }
func (b failedRequestBody) TryReadEOF() (bool, error) { return false, b.err }

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
				if kind == "unexpected_data" {
					if err == nil || len(body) != 0 {
						t.Errorf("invalid zero-length DATA was forwarded: %q, %v", body, err)
					}
					return
				}
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
			wantCalled := kind != "read_error"
			wantStatus := http.StatusOK
			if kind == "read_error" || kind == "unexpected_data" {
				wantStatus = http.StatusBadGateway
			}
			if called != wantCalled || w.Code != wantStatus {
				t.Fatalf("forwarded=%t status=%d", called, w.Code)
			}
		})
	}
}

func TestRequestTrailersThroughBufferedMiddlewareAndReplay(t *testing.T) {
	for _, mode := range []string{"snapshot", "empty_snapshot", "drained"} {
		t.Run(mode, func(t *testing.T) {
			payload := ""
			if mode == "snapshot" {
				payload = "upload"
			}
			testRequestTrailerRewrite(t, mode != "drained", payload)
		})
	}
}

func testRequestTrailerRewrite(t *testing.T, snapshot bool, payload string) {
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
		if r.ContentLength != -1 {
			t.Errorf("buffered request trailers lost streaming framing: length=%d", r.ContentLength)
		}
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
	r.ContentLength = int64(len(payload))
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

func TestBufferedEmptyRequestFraming(t *testing.T) {
	for _, mode := range []string{"snapshot", "replace"} {
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			t.Run(mode+"/"+method, func(t *testing.T) {
				budget := membuffer.NewBudget(4096)
				scope := plugin.Scope{{Host: "example.com", Ports: []uint16{80}}}
				p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: scope}}},
					wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
						return func(e *plugin.Exchange) (*http.Response, error) {
							var view *membuffer.View
							var err error
							if mode == "snapshot" {
								view, err = plugin.SnapshotBody(&e.Request.Body, 1024, budget)
							} else {
								view, err = membuffer.Copy(nil, budget)
								if err == nil {
									plugin.SetRequestBody(e.Request, view)
								}
							}
							if err != nil {
								return nil, err
							}
							defer view.Close()
							return next(e)
						}
					}}
				authority, _ := http3TestAuthority(t)
				h := testHost(t, Options{Authority: authority, BodyMemory: budget}, Instance{Plugin: p})
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// A length-required HTTP/1 upstream must accept the request
					// after inspection or replacement with an empty plugin buffer.
					if r.ContentLength != 0 || r.Header.Get("Content-Length") != "0" || len(r.TransferEncoding) != 0 {
						w.WriteHeader(http.StatusLengthRequired)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer upstream.Close()
				handler := h.handlerForFlow("http", plugin.Flow{Host: "example.com", Port: 80}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
					r.URL.Host = upstream.Listener.Addr().String()
					return upstream.Client().Transport.RoundTrip(r)
				}), http.DefaultClient)
				payload := ""
				if mode == "replace" {
					payload = "original body"
				}
				r := httptest.NewRequest(method, "http://example.com/", strings.NewReader(payload))
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != http.StatusNoContent {
					t.Fatalf("buffered empty request rejected: status=%d body=%q", w.Code, w.Body.String())
				}
				if used := budget.Status().Used; used != 0 {
					t.Fatalf("buffer references leaked: %d bytes", used)
				}
			})
		}
	}
}

func TestIncompleteSnapshotKeepsRequestReadError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
	r.Body = failedRequestBody{err: io.ErrUnexpectedEOF}
	if _, err := plugin.SnapshotBody(&r.Body, 1024, membuffer.NewBudget(4096)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if err := prepareRequestFraming(r); err != nil {
		t.Fatal(err)
	}
	if r.ContentLength != -1 || r.Body == http.NoBody {
		t.Fatal("incomplete empty snapshot was treated as a complete body")
	}
	if _, err := io.ReadAll(r.Body); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost original read error: %v", err)
	}
}
