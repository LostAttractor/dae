// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/common/persist"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/testutil"
)

type scriptStoreMigrationFunc func(context.Context, string, api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error)

func (f scriptStoreMigrationFunc) MigrateScriptStore(ctx context.Context, instance string, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
	return f(ctx, instance, request)
}

func TestScriptStoreAPIValidationAndErrors(t *testing.T) {
	const valid = `{"from_mac":"02-00-00-00-00-AA","to_mac":"02:00:00:00:00:bb"}`
	for _, test := range []struct {
		name, body                                                  string
		noAuth, noMarker, crossOrigin, unix, unavailable, cancelled bool
		storeErr                                                    error
		want, calls                                                 int
	}{
		{name: "admin", want: 200, calls: 1},
		{name: "unix", unix: true, noAuth: true, want: 200, calls: 1},
		{name: "unix no marker", unix: true, noAuth: true, noMarker: true, want: 403},
		{name: "no auth", noAuth: true, want: 401},
		{name: "no marker", noMarker: true, want: 403},
		{name: "cross origin", crossOrigin: true, want: 403},
		{name: "missing", body: `{}`, want: 400},
		{name: "unknown field", body: `{"from_mac":"02:00:00:00:00:aa","to_mac":"02:00:00:00:00:bb","force":true}`, want: 400},
		{name: "duplicate", body: `{"from_mac":"02:00:00:00:00:aa","from_mac":"02:00:00:00:00:bb"}`, want: 400},
		{name: "trailing", body: valid + `{}`, want: 400},
		{name: "same", body: `{"from_mac":"02-00-00-00-00-AA","to_mac":"02:00:00:00:00:aa"}`, want: 400},
		{name: "zero", body: `{"from_mac":"00:00:00:00:00:00","to_mac":"02:00:00:00:00:bb"}`, want: 400},
		{name: "multicast", body: `{"from_mac":"03:00:00:00:00:aa","to_mac":"02:00:00:00:00:bb"}`, want: 400},
		{name: "broadcast", body: `{"from_mac":"ff:ff:ff:ff:ff:ff","to_mac":"02:00:00:00:00:bb"}`, want: 400},
		{name: "eui64", body: `{"from_mac":"02:00:00:00:00:00:00:aa","to_mac":"02:00:00:00:00:bb"}`, want: 400},
		{name: "local", body: `{"from_mac":"local","to_mac":"02:00:00:00:00:bb"}`, want: 400},
		{name: "unknown", body: `{"from_mac":"02:00:00:00:00:aa","to_mac":"unknown"}`, want: 400},
		{name: "no service", unavailable: true, want: 503},
		{name: "invalid", storeErr: plugin.ErrScriptStoreInvalid, want: 400, calls: 1},
		{name: "not found", storeErr: plugin.ErrScriptStoreNotFound, want: 404, calls: 1},
		{name: "conflict", storeErr: plugin.ErrScriptStoreConflict, want: 409, calls: 1},
		{name: "busy", storeErr: plugin.ErrScriptStoreBusy, want: 409, calls: 1},
		{name: "unavailable", storeErr: plugin.ErrScriptStoreUnavailable, want: 503, calls: 1},
		{name: "deadline", storeErr: context.DeadlineExceeded, want: 503, calls: 1},
		{name: "cancelled", cancelled: true, want: 503, calls: 1},
		{name: "private error", storeErr: errors.New("PRIVATE_DATA /secret/store.json"), want: 500, calls: 1},
		{name: "published", storeErr: persist.AfterPublish(fmt.Errorf("PRIVATE_DATA /secret/store.json: %w", context.DeadlineExceeded)), want: 500, calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			options := Options{AdminKey: "secret", ScriptStorage: scriptStoreMigrationFunc(func(ctx context.Context, instance string, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Errorf("missing fixed request budget: %v", deadline)
				}
				if instance != "personal" || request.FromMAC != "02:00:00:00:00:aa" || request.ToMAC != "02:00:00:00:00:bb" {
					t.Errorf("selection or normalization lost: %s %+v", instance, request)
				}
				if test.cancelled {
					return api.ScriptStoreMigrateResponse{}, ctx.Err()
				}
				return api.ScriptStoreMigrateResponse{Instance: instance, FromMAC: request.FromMAC, ToMAC: request.ToMAC, KeysMoved: 2}, test.storeErr
			})}
			if test.unavailable {
				options.ScriptStorage = nil
			}
			body := test.body
			if body == "" {
				body = valid
			}
			r := httptest.NewRequest("POST", "https://192.0.2.1:8081/api/plugins/personal/store/migrate", strings.NewReader(body))
			var local net.Addr = &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8081}
			if test.unix {
				local = &net.UnixAddr{Name: "dae.sock", Net: "unix"}
			}
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), http.LocalAddrContextKey, local))
			defer cancel()
			if test.cancelled {
				cancel()
			}
			r = r.WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			if !test.noAuth {
				r.Header.Set("Authorization", "Bearer secret")
			}
			if !test.noMarker {
				r.Header.Set("X-Dae-API", "1")
			}
			if test.crossOrigin {
				r.Header.Set("Origin", "http://evil.example")
			}
			w := httptest.NewRecorder()
			NewHandler(options).ServeHTTP(w, r)
			if w.Code != test.want || calls != test.calls || strings.Contains(w.Body.String(), "PRIVATE_DATA") || strings.Contains(w.Body.String(), "/secret/") {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body)
			}
			if test.name == "published" && !strings.Contains(w.Body.String(), "was published, but durability is unconfirmed") {
				t.Fatalf("published outcome lost: %s", w.Body)
			}
			if test.want == 200 {
				var response api.ScriptStoreMigrateResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.KeysMoved != 2 || response.Instance != "personal" || response.FromMAC != "02:00:00:00:00:aa" || response.ToMAC != "02:00:00:00:00:bb" {
					t.Fatalf("response: %+v %v", response, err)
				}
			}
		})
	}
}

func TestScriptStoreAPIClientRoundTrip(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(NewHandler(Options{AdminKey: "secret", ScriptStorage: scriptStoreMigrationFunc(func(ctx context.Context, instance string, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
		calls++
		if instance != "personal / store" || request.FromMAC != "02:00:00:00:00:aa" || request.ToMAC != "02:00:00:00:00:bb" {
			t.Errorf("request lost: %s %+v", instance, request)
		}
		if calls > 1 {
			return api.ScriptStoreMigrateResponse{}, persist.AfterPublish(errors.New("PRIVATE_DATA"))
		}
		return api.ScriptStoreMigrateResponse{Instance: instance, FromMAC: request.FromMAC, ToMAC: request.ToMAC, KeysMoved: 4}, nil
	})}))
	defer server.Close()
	remote, err := client.New(client.Options{Endpoint: server.URL, RootCAs: testutil.TLSRoots(server), APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	request := api.ScriptStoreMigrateRequest{FromMAC: "02-00-00-00-00-AA", ToMAC: "02:00:00:00:00:bb"}
	response, err := remote.MigrateScriptStore(t.Context(), "personal / store", request)
	if err != nil || response.KeysMoved != 4 || response.FromMAC != "02:00:00:00:00:aa" {
		t.Fatalf("round trip: %+v %v", response, err)
	}
	_, err = remote.MigrateScriptStore(t.Context(), "personal / store", request)
	apiErr, ok := errors.AsType[*client.Error](err)
	if !ok || apiErr.StatusCode != 500 || !strings.Contains(err.Error(), "durability is unconfirmed") || strings.Contains(err.Error(), "PRIVATE_DATA") || calls != 2 {
		t.Fatalf("published outcome lost or retried: %v calls=%d", err, calls)
	}
}
