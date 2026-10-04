// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/component/plugin"
)

type scriptTriggerFunc func(string, api.ScriptRunRequest) (api.ScriptRunResponse, error)

func (f scriptTriggerFunc) TriggerScript(instance string, request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
	return f(instance, request)
}

func TestScriptAPIValidationAndErrors(t *testing.T) {
	for _, test := range []struct {
		name, body, key, marker, origin string
		storeErr                        error
		want, calls                     int
	}{
		{name: "accepted", body: `{"script":"签到","module":"youpin"}`, key: "secret", marker: "1", want: 202, calls: 1},
		{name: "no auth", body: `{"script":"签到"}`, marker: "1", want: 401},
		{name: "no marker", body: `{"script":"签到"}`, key: "secret", want: 403},
		{name: "cross origin", body: `{"script":"签到"}`, key: "secret", marker: "1", origin: "http://evil.example", want: 403},
		{name: "missing script", body: `{}`, key: "secret", marker: "1", want: 400},
		{name: "inline source", body: `{"script":"签到","source":"$done()"}`, key: "secret", marker: "1", want: 400},
		{name: "duplicate key", body: `{"script":"a","script":"b"}`, key: "secret", marker: "1", want: 400},
		{name: "missing task", body: `{"script":"签到"}`, key: "secret", marker: "1", storeErr: plugin.ErrScriptNotFound, want: 404, calls: 1},
		{name: "ambiguous", body: `{"script":"签到"}`, key: "secret", marker: "1", storeErr: plugin.ErrScriptAmbiguous, want: 400, calls: 1},
		{name: "busy", body: `{"script":"签到"}`, key: "secret", marker: "1", storeErr: plugin.ErrScriptBusy, want: 409, calls: 1},
		{name: "inactive", body: `{"script":"签到"}`, key: "secret", marker: "1", storeErr: plugin.ErrScriptInactive, want: 503, calls: 1},
		{name: "internal", body: `{"script":"签到"}`, key: "secret", marker: "1", storeErr: errors.New("PRIVATE_DATA"), want: 500, calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			handler := NewHandler(Options{APIKey: "secret", Scripts: scriptTriggerFunc(func(instance string, request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
				calls++
				if instance != "personal" || request.Script != "签到" || (test.want == 202 && request.Module != "youpin") {
					t.Errorf("wrong selection: %s %+v", instance, request)
				}
				return api.ScriptRunResponse{Instance: instance, Module: "youpin", Run: 3, Status: api.ScriptTaskStatus{Name: request.Script, Type: "cron", Runs: 3, State: "waiting", LastTrigger: "http-api"}}, test.storeErr
			})})
			r := httptest.NewRequest("POST", "http://192.0.2.1:8081/api/plugins/personal/scripts/run", strings.NewReader(test.body))
			r = r.WithContext(context.WithValue(t.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8081}))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Dae-API", test.marker)
			if test.key != "" {
				r.Header.Set("Authorization", "Bearer "+test.key)
			}
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.want || calls != test.calls || strings.Contains(w.Body.String(), "PRIVATE_DATA") {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body)
			}
			if test.want == 202 {
				var response api.ScriptRunResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Run != 3 || response.Status.LastResult != "" {
					t.Fatalf("invalid acceptance response: %+v %v", response, err)
				}
			}
		})
	}
}

func TestScriptAPIClientRoundTrip(t *testing.T) {
	calls := 0
	server := httptest.NewServer(NewHandler(Options{APIKey: "secret", Scripts: scriptTriggerFunc(func(instance string, request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
		calls++
		if instance != "personal" || request.Module != "小米有品" || request.Script != "有品签到" {
			t.Errorf("selection lost: %s %+v", instance, request)
		}
		if calls == 2 {
			return api.ScriptRunResponse{}, plugin.ErrScriptBusy
		}
		return api.ScriptRunResponse{Instance: instance, Module: request.Module, Run: 1, Status: api.ScriptTaskStatus{Name: request.Script, Type: "generic", Runs: 1, State: "waiting"}}, nil
	})}))
	defer server.Close()
	remote, err := client.New(client.Options{Endpoint: server.URL, APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	request := api.ScriptRunRequest{Module: "小米有品", Script: "有品签到"}
	response, err := remote.TriggerScript(t.Context(), "personal", request)
	if err != nil || response.Instance != "personal" || response.Run != 1 || response.Status.State != "waiting" || response.Status.Type != "generic" {
		t.Fatalf("API client: %+v %v", response, err)
	}
	_, err = remote.TriggerScript(t.Context(), "personal", request)
	apiErr, ok := errors.AsType[*client.Error](err)
	if !ok || apiErr.StatusCode != 409 || calls != 2 {
		t.Fatalf("conflict was lost or automatically retried: %v, calls=%d", err, calls)
	}
}
