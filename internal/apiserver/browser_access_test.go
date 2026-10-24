// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestProxyRequestsOnlyLoseDirectCapabilities(t *testing.T) {
	resolved := 0
	h := NewHandler(Options{
		AdminKey: "admin", AllowLANAnonymous: true, Selectors: &sessionSelectors{},
		Certificates: &Certificates{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })},
		ResolveClient: func(source, dest netip.AddrPort) (api.ClientIdentity, error) {
			resolved++
			return verifiedTestLAN(source, dest)
		},
	})
	for _, marker := range []string{"X-Dae-Proxy", "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-IP"} {
		t.Run(marker, func(t *testing.T) {
			for _, route := range []struct {
				method, path string
				status       int
			}{
				{"GET", "/api/selectors", 200},
				{"GET", "/api/certificate", 200},
				{"GET", "/api/certificate/ca.pem", 200},
				{"DELETE", "/api/selectors/proxy", 200},
				{"GET", "/api/device", 403},
				{"GET", "/api/device/context", 403},
				{"POST", "/api/device/diagnostics/explain", 403},
				{"POST", "/api/device/mitm-tests", 403},
				{"POST", "/api/certificate/tests", 403},
				{"GET", "/api/certificate/tests/proof", 403},
			} {
				w := sessionRequest(t, h, route.method, route.path, "", map[string]string{marker: "", "Authorization": "Bearer admin", "X-Dae-API": "1"})
				if w.Code != route.status {
					t.Fatalf("%s: %d %s", route.path, w.Code, w.Body.String())
				}
			}
			w := sessionRequest(t, h, "GET", "/api/selectors", "", map[string]string{marker: ""})
			if w.Code != 401 {
				t.Fatal("proxy inherited anonymous LAN", w.Code)
			}
		})
	}
	if resolved != 0 {
		t.Fatal("proxy requests consulted LAN identity", resolved)
	}
	for _, local := range []net.Addr{&net.UnixAddr{Net: "unix", Name: "dae.sock"}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}} {
		r := httptest.NewRequestWithContext(t.Context(), "GET", "http://192.0.2.1:9080/api/selectors", nil)
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
		r.Header.Set("X-Dae-Proxy", "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("proxy accepted HTTP or Unix upstream", local, w.Code)
		}
	}
}

func TestBrowserOriginErrorsAndMonitoringCookies(t *testing.T) {
	h := NewHandler(Options{
		AdminKey: "admin", Selectors: &sessionSelectors{}, WebOrigins: []string{"https://WEB.example:443"}, Pprof: true,
		Metrics: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("metric 1")) }),
	})
	cookie := loginCookie(t, h, "admin")
	for _, path := range []string{"/api/selectors", "/metrics", "/debug/pprof/goroutine?debug=1"} {
		for _, credential := range []string{"", cookie.Name + "=invalid", cookie.Name + "=" + cookie.Value} {
			w := sessionRequest(t, h, "GET", path, "", map[string]string{"Origin": "https://web.example", "Cookie": credential, "Sec-Fetch-Site": "same-site"})
			want := 401
			if strings.HasSuffix(credential, cookie.Value) {
				want = 200
			}
			if w.Code != want || w.Header().Get("Access-Control-Allow-Origin") != "https://web.example" || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
				t.Fatal(path, w.Code, w.Header(), w.Body.String())
			}
		}
		w := sessionRequest(t, h, "GET", path, "", map[string]string{"Origin": "https://web.example", "Cookie": cookie.Name + "=" + cookie.Value, "Sec-Fetch-Site": "cross-site"})
		if w.Code != 403 {
			t.Fatal("cross-site cookie reached protected handler", path, w.Code)
		}
	}
	preflight := sessionRequest(t, h, "OPTIONS", "/api/session", "", map[string]string{
		"Origin": "https://web.example", "Sec-Fetch-Site": "cross-site",
		"Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "authorization,x-dae-api",
	})
	if preflight.Code != 204 || preflight.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("preflight hid the actual cross-site error", preflight.Code, preflight.Header())
	}
	crossSite := sessionRequest(t, h, "PUT", "/api/session", "", map[string]string{
		"Origin": "https://web.example", "Sec-Fetch-Site": "cross-site", "Authorization": "Bearer admin", "X-Dae-API": "1",
	})
	if crossSite.Code != 403 || crossSite.Header().Get("Access-Control-Allow-Origin") != "https://web.example" || len(crossSite.Result().Cookies()) != 0 {
		t.Fatal("cross-site key login must fail readably without a cookie", crossSite.Code, crossSite.Header())
	}
	for _, method := range []string{"PUT", "DELETE"} {
		w := sessionRequest(t, h, method, "/api/session", "", map[string]string{"Origin": "https://web.example"})
		if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "https://web.example" {
			t.Fatal("unreadable mutation error", w.Code, w.Header())
		}
	}
}

func TestMobileConfigNavigationRequiresApprovedSameSiteSource(t *testing.T) {
	const source = "https://192.0.2.1:8443"
	const profile = "/api/certificate/ca.mobileconfig"
	h := NewHandler(Options{
		UserKey: "user", WebOrigins: []string{source, "http://192.0.2.1:8443"}, Selectors: &sessionSelectors{},
		Certificates: &Certificates{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })},
	})
	cookie := loginCookie(t, h, "user")
	for _, test := range []struct {
		name, path, site, mode, dest, referrer string
		withCookie                             bool
		want                                   int
	}{
		{"allowed navigation", profile, "same-site", "navigate", "document", source + "/", true, 200},
		{"no session", profile, "same-site", "navigate", "document", source + "/", false, 401},
		{"cross-site", profile, "cross-site", "navigate", "document", source + "/", true, 403},
		{"unlisted port", profile, "same-site", "navigate", "document", "https://192.0.2.1:8444/", true, 403},
		{"insecure source", profile, "same-site", "navigate", "document", "http://192.0.2.1:8443/", true, 403},
		{"no referrer", profile, "same-site", "navigate", "document", "", true, 403},
		{"frame", profile, "same-site", "navigate", "iframe", source + "/", true, 403},
		{"fetch", profile, "same-site", "cors", "empty", source + "/", true, 403},
		{"other API", "/api/selectors", "same-site", "navigate", "document", source + "/", true, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			headers := map[string]string{"Sec-Fetch-Site": test.site, "Sec-Fetch-Mode": test.mode, "Sec-Fetch-Dest": test.dest}
			if test.referrer != "" {
				headers["Referer"] = test.referrer
			}
			if test.withCookie {
				headers["Cookie"] = cookie.Name + "=" + cookie.Value
			}
			w := sessionRequest(t, h, "GET", test.path, "", headers)
			if w.Code != test.want || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal(w.Code, w.Header(), w.Body.String())
			}
		})
	}
}
