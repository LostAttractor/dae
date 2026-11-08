// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

func TestHTTPStageMetricsAndFirstEvents(t *testing.T) {
	for _, level := range []log.Level{log.InfoLevel, log.TraceLevel} {
		for _, fail := range []bool{false, true} {
			t.Run(level.String()+"/"+map[bool]string{false: "success", true: "error"}[fail], func(t *testing.T) {
				logger, hook, _ := observationLogger()
				logger.Logger.SetLevel(level)
				p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
					return func(e *plugin.Exchange) (*plugin.Response, error) {
						view, err := e.Request.Body().Snapshot(64)
						if err != nil {
							return nil, err
						}
						view.Close()
						r, err := next(e)
						if err != nil {
							return nil, err
						}
						view, err = r.Body().Snapshot(64)
						if err != nil {
							_ = r.Close()
							return nil, err
						}
						view.Close()
						r.SetDelivery(plugin.DeliveryStreaming)
						return r, nil
					}
				}}
				h := testHost(t, Options{Authority: &localca.Authority{}, Logger: logger}, Instance{ID: "test", Plugin: p})
				handler := h.handlerForFlow("http", plugin.Flow{Host: "example.com", Port: 80}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
					_ = r.Body.Close()
					if fail {
						return nil, errors.New("fixture failure")
					}
					return response("ok"), nil
				}), nil)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("POST", "http://example.com/", strings.NewReader("request")))
				wantStatus := http.StatusOK
				if fail {
					wantStatus = http.StatusBadGateway
				}
				if w.Code != wantStatus {
					t.Fatal(w.Code, w.Body.String())
				}
				families, err := h.metrics.Gather()
				if err != nil {
					t.Fatal(err)
				}
				counts := map[string]uint64{}
				for _, family := range families {
					if family.GetName() != "dae_mitm_http_stage_duration_seconds" {
						continue
					}
					for _, metric := range family.Metric {
						counts[metric.Label[0].GetValue()] = metric.GetHistogram().GetSampleCount()
					}
				}
				wantSnapshots := uint64(2)
				if fail {
					wantSnapshots = 1
				}
				for stage, want := range map[string]uint64{"upstream": 1, "response_ready": 1, "request": 1, "snapshot": wantSnapshots} {
					if counts[stage] != want {
						t.Errorf("%s = %d, want %d", stage, counts[stage], want)
					}
				}
				if level == log.TraceLevel && !fail {
					events := map[string]int{}
					for _, entry := range hook.AllEntries() {
						if name, ok := entry.Data["event"].(string); ok {
							events[name]++
						}
					}
					for _, name := range []string{"mitm_response_ready", "mitm_response_first_read", "mitm_response_first_data", "mitm_response_first_write", "mitm_response_first_flush", "mitm_request_end"} {
						if events[name] != 1 {
							t.Errorf("%s = %d", name, events[name])
						}
					}
				}
			})
		}
	}
}

func BenchmarkHTTPHandler(b *testing.B) {
	for _, level := range []log.Level{log.InfoLevel, log.DebugLevel} {
		b.Run(level.String(), func(b *testing.B) {
			logger := log.New()
			logger.SetLevel(level)
			logger.SetOutput(io.Discard)
			p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler { return next }}
			h := testHost(b, Options{Authority: &localca.Authority{}, Logger: log.NewEntry(logger)}, Instance{ID: "test", Plugin: p})
			handler := h.handlerForFlow("http", plugin.Flow{Host: "example.com", Port: 80}, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
			}), nil)
			b.ReportAllocs()
			for b.Loop() {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
				if w.Code != http.StatusOK {
					b.Fatal(w.Code)
				}
			}
		})
	}
}
