// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestRequestOwnershipEndsAfterUpstreamOrLocalResponse(t *testing.T) {
	for _, outcome := range []string{"response", "local", "error", "abort", "body_error"} {
		t.Run(outcome, func(t *testing.T) {
			budget := membuffer.NewBudget(1 << 20)
			payload := strings.Repeat("final", 32768)
			p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
				return func(e *plugin.Exchange) (*http.Response, error) {
					// Multiple request plugins can replace and inspect the same body.
					for _, text := range []string{"first", payload} {
						view, err := membuffer.Copy([]byte(text), budget)
						if err != nil {
							return nil, err
						}
						plugin.SetRequestBody(e.Request, view)
						view.Close()
						snapshot, err := plugin.SnapshotBody(&e.Request.Body, int64(len(payload)), budget)
						snapshot.Close()
						if err != nil {
							return nil, err
						}
					}
					switch outcome {
					case "local":
						return response("local"), nil
					case "error":
						return nil, errors.New("plugin failed")
					case "abort":
						return nil, plugin.ErrAbort
					}
					return next(e)
				}
			}}
			h := testHost(t, Options{Authority: &mitmca.Authority{}}, Instance{Plugin: p})
			upstreamCalls := 0
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				upstreamCalls++
				_ = req.Body.Close() // A transport can close the first attempt before retrying.
				retry, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				got, err := io.ReadAll(retry)
				_ = retry.Close()
				if err != nil || string(got) != payload {
					t.Fatalf("retry: %q %v", got, err)
				}
				r := response("")
				r.Body = &ownershipResponse{check: func() {
					if budget.Status().Used != 0 {
						t.Error("retained request retry storage while forwarding response")
					}
				}, fail: outcome == "body_error"}
				return r, nil
			})
			handler := h.handlerForFlow("https", plugin.Flow{Host: "example.com", Port: 443}, transport, http.DefaultClient)
			recorder := httptest.NewRecorder()
			func() {
				defer func() {
					err := recover()
					if outcome == "abort" || outcome == "body_error" {
						if err != http.ErrAbortHandler {
							t.Fatalf("expected abort, got %v", err)
						}
					} else if err != nil {
						panic(err)
					}
				}()
				req := httptest.NewRequest("POST", "https://example.com/", strings.NewReader("original"))
				// ReverseProxy propagates body copy errors as it does inside a server.
				req = req.WithContext(context.WithValue(req.Context(), http.ServerContextKey, &http.Server{}))
				handler.ServeHTTP(recorder, req)
			}()
			wantCalls := 0
			if outcome == "response" || outcome == "body_error" {
				wantCalls = 1
			}
			if upstreamCalls != wantCalls {
				t.Fatalf("upstream calls=%d, want %d", upstreamCalls, wantCalls)
			}
			wantStatus := http.StatusOK
			if outcome == "error" {
				wantStatus = http.StatusBadGateway
			}
			if outcome != "abort" && recorder.Code != wantStatus {
				t.Fatalf("status=%d, want %d", recorder.Code, wantStatus)
			}
			if used := budget.Status().Used; used != 0 {
				t.Fatalf("retained %d bytes after %s", used, outcome)
			}
		})
	}
}

type ownershipResponse struct {
	check func()
	fail  bool
}

func (r *ownershipResponse) Read([]byte) (int, error) {
	r.check()
	if r.fail {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}
func (*ownershipResponse) Close() error { return nil }
