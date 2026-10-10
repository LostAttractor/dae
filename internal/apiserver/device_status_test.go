// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestDeviceStatusRequiresLANIdentityEvenWithAdminKey(t *testing.T) {
	for _, verified := range []bool{false, true} {
		called := false
		handler := NewHandler(Options{APIKey: "secret", ResolveClient: func(source, destination netip.AddrPort) ([6]byte, error) {
			if !verified {
				return [6]byte{}, errors.New("not a LAN peer")
			}
			return [6]byte{2, 1}, nil
		}, DeviceStatus: func(ip netip.Addr, mac [6]byte) api.DeviceStatus {
			called = true
			if ip.String() != "192.0.2.2" || mac != [6]byte{2, 1} {
				t.Fatal("untrusted identity reached status")
			}
			return api.DeviceStatus{Scope: "userspace_upstream"}
		}})
		r := httptest.NewRequest("GET", "http://192.0.2.1:9080/api/device/status", nil)
		r.RemoteAddr = "192.0.2.2:45000"
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("X-Forwarded-For", "192.0.2.99")
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if verified != (w.Code == 200) || called != verified {
			t.Fatalf("verified=%v status=%d called=%v", verified, w.Code, called)
		}
	}
}
