package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMITMOriginHandlesDefaultPortAndIPv6(t *testing.T) {
	for _, test := range []struct {
		host, origin, local string
		status              int
	}{
		{"192.0.2.1:80", "http://192.0.2.1", "192.0.2.1:80", 200},
		{"192.0.2.1", "http://192.0.2.1:80", "192.0.2.1:80", 200},
		{"192.0.2.1:80", "http://192.0.2.1:81", "192.0.2.1:80", 403},
		{"[2001:db8::1]:8081", "http://[2001:db8::1]:8081", "[2001:db8::1]:8081", 200},
	} {
		local, err := net.ResolveTCPAddr("tcp", test.local)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("GET", "http://"+test.host+"/api/device/mitm", nil)
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, local))
		request.Header.Set("Origin", test.origin)
		allowed := localIPHost(request) && sameOrigin(request)
		if allowed != (test.status == 200) {
			t.Errorf("host=%s origin=%s allowed=%v", test.host, test.origin, allowed)
		}
	}
}
