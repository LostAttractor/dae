// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

// Only reads are expected in this rejection suite. State changes must never
// reach the runtime store, regardless of which request guard rejects them.
type rejectedDeviceMutations struct {
	DeviceStore
	t *testing.T
}

func (s rejectedDeviceMutations) DeviceState(netip.Addr, [6]byte) api.DeviceState {
	return api.DeviceState{}
}

func (s rejectedDeviceMutations) UpdateMITM(netip.Addr, [6]byte, *bool) (api.DeviceState, error) {
	s.t.Error("invalid request reached state mutation")
	return api.DeviceState{}, nil
}

func TestMITMDeviceAPIRejectsCrossOriginAndMalformedChanges(t *testing.T) {
	const fingerprint = "current CA fingerprint"
	options := Options{
		Devices: rejectedDeviceMutations{t: t},
		Certificates: &Certificates{
			Identity: api.Certificate{Name: "device API", Fingerprint: fingerprint},
			Handler:  http.NotFoundHandler(),
		},
	}
	for _, test := range []struct {
		name, method, body, origin, site, contentType, marker, query, host string
		status                                                             int
	}{
		{name: "status", method: "GET", status: 200},
		{name: "foreign origin", method: "PUT", body: `{"enabled":true}`, contentType: "application/json", marker: fingerprint, origin: "http://evil.example", status: 403},
		{name: "foreign status", method: "GET", origin: "http://evil.example", status: 403},
		{name: "null origin", method: "GET", origin: "null", status: 403},
		{name: "foreign scheme", method: "GET", origin: "https://192.0.2.1:8081", status: 403},
		{name: "DNS rebinding", method: "GET", host: "evil.example:8081", origin: "http://evil.example:8081", status: 403},
		{name: "wrong local IP", method: "GET", host: "192.0.2.2:8081", status: 403},
		{name: "wrong local port", method: "GET", host: "192.0.2.1:9999", status: 403},
		{name: "cross-site metadata", method: "GET", site: "cross-site", status: 403},
		{name: "same-site metadata", method: "DELETE", marker: fingerprint, site: "same-site", status: 403},
		{name: "form mutation", method: "POST", body: "enabled=true", status: 405},
		{name: "preflight", method: "OPTIONS", status: 405},
		{name: "missing fingerprint", method: "DELETE", status: 403},
		{name: "stale fingerprint", method: "PUT", body: `{"enabled":true}`, contentType: "application/json", marker: "old CA", status: 409},
		{name: "text JSON", method: "PUT", body: `{"enabled":true}`, contentType: "text/plain", marker: fingerprint, status: 415},
		{name: "empty object", method: "PUT", body: `{}`, contentType: "application/json", marker: fingerprint, status: 400},
		{name: "null", method: "PUT", body: `{"enabled":null}`, contentType: "application/json", marker: fingerprint, status: 400},
		{name: "MAC injection", method: "PUT", body: `{"enabled":true,"mac":"00:11:22:33:44:55"}`, contentType: "application/json", marker: fingerprint, status: 400},
		{name: "duplicate property", method: "PUT", body: `{"enabled":false,"enabled":true}`, contentType: "application/json", marker: fingerprint, status: 400},
		{name: "trailing data", method: "PUT", body: `{"enabled":true}{}`, contentType: "application/json", marker: fingerprint, status: 400},
		{name: "oversize", method: "PUT", body: strings.Repeat(" ", 1025), contentType: "application/json", marker: fingerprint, status: 413},
		{name: "query injection", method: "GET", query: "?source=192.0.2.99", status: 400},
		{name: "GET body", method: "GET", body: `{"enabled":true}`, status: 400},
		{name: "DELETE body", method: "DELETE", marker: fingerprint, body: `{"mac":"00:11:22:33:44:55"}`, status: 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			options.ResolveClient = func(peer, _ netip.AddrPort) ([6]byte, error) {
				ip := peer.Addr()
				called = true
				if ip != netip.MustParseAddr("192.0.2.10") {
					t.Fatalf("untrusted peer identity: %s", ip)
				}
				return [6]byte{2, 0, 0, 0, 0, 10}, nil
			}
			handler := NewHandler(options)
			path := "http://192.0.2.1:8081/api/device"
			if test.method != http.MethodGet {
				path += "/mitm"
			}
			request := httptest.NewRequest(test.method, path+test.query, strings.NewReader(test.body))
			request.RemoteAddr = "[::ffff:192.0.2.10]:45000"
			request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8081}))
			if test.host != "" {
				request.Host = test.host
			}
			request.Header.Set("X-Dae-API", "1")
			for key, value := range map[string]string{"Origin": test.origin, "Sec-Fetch-Site": test.site, "Content-Type": test.contentType, "X-Dae-MITM": test.marker} {
				if value != "" {
					request.Header.Set(key, value)
				}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || called != (test.status == 200) {
				t.Fatalf("status=%d called=%v body=%s", response.Code, called, response.Body.String())
			}
			if response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("API allowed CORS or cached a device state")
			}
			if test.status != 200 && test.status != http.StatusMethodNotAllowed {
				var result struct{ Error string }
				if err := json.Unmarshal(response.Body.Bytes(), &result, json.MatchCaseInsensitiveNames(true)); err != nil || result.Error == "" {
					t.Fatalf("failure lacks a JSON error: %v, %s", err, response.Body.String())
				}
			}
		})
	}
}
