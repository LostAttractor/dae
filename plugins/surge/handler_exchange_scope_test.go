// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestHTTPExchangeSharesIdentityAcrossInstances(t *testing.T) {
	for _, sharedFirst := range []bool{false, true} {
		name := "isolated-first"
		if sharedFirst {
			name = "shared-first"
		}
		t.Run(name, func(t *testing.T) {
			isolated := moduleScopeEngine(t, moduleScopeModule(t, "isolated", "example.com", `[Script]
request=type=http-request,pattern=.,script-path=request.js
response=type=http-response,pattern=.,script-path=response.js`, map[string]string{
				"request":  `$persistentStore.write("saved", "cookie"); $done();`,
				"response": `$done({headers:{"X-Cookie":String($persistentStore.read("cookie"))}});`,
			}))
			shared := moduleScopeEngine(t, moduleScopeModule(t, "shared", "example.com", `[Script]
request=type=http-request,pattern=.,script-path=shared.js`, map[string]string{
				"request": `$persistentStore.write("shared", "cookie"); $done();`,
			}))
			isolated.options.IsolateLAN, shared.options.IsolateLAN = true, false
			isolated.options.ScriptTimeout, shared.options.ScriptTimeout = time.Second, 5*time.Second
			devices := newTestDevices()
			var calls atomic.Uint32
			devices.identify = func(ctx context.Context, _ netip.Addr, mac [6]byte) [6]byte {
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
					t.Errorf("identity did not use the first isolated script's deadline: %v", deadline)
				}
				if calls.Add(1) == 1 {
					return mac
				}
				return [6]byte{}
			}
			isolated.options.Devices, shared.options.Devices = devices, devices
			flow := plugin.Flow{Host: "example.com", Port: 443, Source: netip.MustParseAddrPort("192.0.2.1:12345"), SourceOrigin: plugin.SourceLAN, SourceMAC: testDeviceMAC}
			request := plugin.NewRequest(httptest.NewRequest("POST", "https://example.com/", strings.NewReader("request body")), isolated.options.BodyMemory)
			head := request.Head
			terminal := func(exchange *plugin.Exchange) (*plugin.Response, error) {
				if exchange.Request.Head != head {
					t.Fatal("scope installation replaced the owned request head")
				}
				forwarded := forwardTestRequest(t, exchange.Request)
				body, err := io.ReadAll(forwarded.Body)
				forwarded.Body.Close()
				if err != nil || string(body) != "request body" {
					t.Fatalf("scope installation changed the owned request body: %q %v", body, err)
				}
				return exchange.NewResponse(&http.Response{StatusCode: http.StatusOK, Request: forwarded, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("response body")), ContentLength: 13}), nil
			}
			first, second := isolated, shared
			if sharedFirst {
				first, second = shared, isolated
			}
			handler := first.Wrap(flow, second.Wrap(flow, terminal))
			response, err := handler(&plugin.Exchange{Request: request, Client: http.DefaultClient})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Close()
			if value := response.Head.Header.Get("X-Cookie"); value != "saved" || calls.Load() != 1 {
				t.Fatalf("exchange identity changed: cookie=%q identifyCalls=%d", value, calls.Load())
			}
			wire := takeTestResponse(t, response)
			body, err := io.ReadAll(wire.Body)
			wire.Body.Close()
			if err != nil || string(body) != "response body" {
				t.Fatalf("scope installation changed the owned response body: %q %v", body, err)
			}
			for _, test := range []struct {
				engine *Engine
				scope  ScriptScope
				want   any
			}{
				{isolated, testDeviceScope, "saved"},
				{isolated, testLocalScope, nil},
				{shared, testLocalScope, "shared"},
				{shared, testDeviceScope, nil},
			} {
				value, err := test.engine.options.Runtime.data.read(t.Context(), test.scope, "cookie")
				if err != nil || value != test.want {
					t.Fatalf("instance policy changed: scope=%v value=%v want=%v err=%v", test.scope, value, test.want, err)
				}
			}
		})
	}
}
