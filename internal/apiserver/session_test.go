// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

type sessionSelectors struct{ state api.SelectorState }

func (s *sessionSelectors) Selectors() []api.SelectorState { return []api.SelectorState{s.state} }
func (s *sessionSelectors) Select(group, node, _ string) (api.SelectorState, error) {
	s.state = api.SelectorState{Name: group, NodeID: node}
	return s.state, nil
}
func rejectLANClient(netip.AddrPort, netip.AddrPort) (api.ClientIdentity, error) {
	return api.ClientIdentity{}, net.ErrClosed
}
func sessionRequest(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "https://192.0.2.1:9080"+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.10:45000"
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func loginCookie(t *testing.T, h http.Handler, key string) *http.Cookie {
	t.Helper()
	w := sessionRequest(t, h, "PUT", "/api/session", "", map[string]string{"Authorization": "Bearer " + key, "X-Dae-API": "1", "Origin": "https://192.0.2.1:9080"})
	var session api.Session
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &session) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies: %v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || cookie.Value == "" || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	if (key != session.Role && strings.Contains(cookie.Value, key)) || strings.Contains(w.Body.String(), cookie.Value) || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatal("login disclosed a credential to JavaScript")
	}
	if !cookie.Expires.Equal(session.ExpiresAt) || time.Until(cookie.Expires) > sessionLifetime || time.Until(cookie.Expires) < sessionLifetime-time.Minute {
		t.Fatal("incorrect absolute session expiration")
	}
	return cookie
}

func TestScopedSessionsAndRotation(t *testing.T) {
	options := Options{UserKey: "user-secret", AdminKey: "admin-secret", Selectors: &sessionSelectors{}}
	for _, key := range []string{options.UserKey, options.AdminKey} {
		cookie := loginCookie(t, NewHandler(options), key)
		role, ok := NewHandler(options).sessionRole(cookie.Value, "192.0.2.1:9080")
		if !ok || (role == roleAdmin) != (key == options.AdminKey) {
			t.Fatal("session role lost")
		}
		for _, host := range []string{"192.0.2.2:9080", "192.0.2.1:9081"} {
			if _, ok := NewHandler(options).sessionRole(cookie.Value, host); ok {
				t.Fatal("session transferred between API origins")
			}
		}
		updated := options
		if role == roleAdmin {
			updated.AdminKey = "rotated"
		} else {
			updated.UserKey = "rotated"
		}
		if _, ok := NewHandler(updated).sessionRole(cookie.Value, "192.0.2.1:9080"); ok {
			t.Fatal("rotation retained old session")
		}
		updated = options
		if role == roleAdmin {
			updated.UserKey = "rotated"
		} else {
			updated.AdminKey = "rotated"
		}
		if _, ok := NewHandler(updated).sessionRole(cookie.Value, "192.0.2.1:9080"); !ok {
			t.Fatal("unrelated role rotation invalidated session")
		}
		w := sessionRequest(t, NewHandler(options), "DELETE", "/api/selectors/proxy", "", map[string]string{"Cookie": cookie.Name + "=" + cookie.Value, "Sec-Fetch-Site": "same-origin", "X-Dae-API": "1"})
		want := 200
		if role == roleUser {
			want = 403
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestSessionCannotRenewAndLogoutClearsExpiredCookie(t *testing.T) {
	h := NewHandler(Options{AdminKey: "admin", AllowLANAnonymous: true, ResolveClient: verifiedTestLAN, Selectors: &sessionSelectors{}})
	payload := "dae1.admin." + strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10) + ".nonce"
	token := payload + "." + base64.RawURLEncoding.EncodeToString(sessionSignature(payload, "192.0.2.1:9080", "admin"))
	for _, headers := range []map[string]string{
		{"Cookie": sessionCookieName + "=" + token},
		{"Authorization": "Bearer " + token},
		{},
	} {
		headers["Sec-Fetch-Site"], headers["X-Dae-API"] = "same-origin", "1"
		w := sessionRequest(t, h, "PUT", "/api/session", "", headers)
		if w.Code != 401 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("login without raw key minted a session", w.Code, w.Body.String())
		}
	}
	for _, cookie := range []string{token, "expired"} {
		w := sessionRequest(t, h, "DELETE", "/api/session", "", map[string]string{"Cookie": sessionCookieName + "=" + cookie, "Sec-Fetch-Site": "same-origin", "X-Dae-API": "1"})
		cookies := w.Result().Cookies()
		if w.Code != 204 || len(cookies) != 1 || cookies[0].MaxAge != -1 || cookies[0].Value != "" || cookies[0].Path != "/" || !cookies[0].Secure || !cookies[0].HttpOnly {
			t.Fatal("logout did not clear the cookie", w.Code, w.Header())
		}
	}
	if w := accessRequest(t, h, "PUT", "/api/session", "", "", false, true); w.Code != 403 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("Unix identity minted a browser session", w.Code)
	}
}

func TestSessionCredentialPrecedenceAndBrowserBoundary(t *testing.T) {
	h := NewHandler(Options{AdminKey: "admin", AllowLANAnonymous: true, ResolveClient: verifiedTestLAN, Selectors: &sessionSelectors{}, WebOrigins: []string{"https://192.0.2.1:5173"}})
	cookie := loginCookie(t, h, "admin")
	value := cookie.Name + "=" + cookie.Value
	for _, test := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"same-origin", map[string]string{"Cookie": value, "Sec-Fetch-Site": "same-origin"}, 200},
		{"same-site", map[string]string{"Cookie": value, "Origin": "https://192.0.2.1:5173", "Sec-Fetch-Site": "same-site"}, 200},
		{"cross-site", map[string]string{"Cookie": value, "Origin": "https://192.0.2.1:5173", "Sec-Fetch-Site": "cross-site"}, 403},
		{"unlisted origin", map[string]string{"Cookie": value, "Origin": "https://other.example"}, 403},
		{"missing origin", map[string]string{"Cookie": value}, 403},
		{"bad cookie never LAN", map[string]string{"Cookie": cookie.Name + "=bad", "Sec-Fetch-Site": "same-origin"}, 401},
		{"bad key never cookie", map[string]string{"Cookie": value, "Authorization": "Bearer bad", "Sec-Fetch-Site": "same-origin"}, 401},
		{"empty key never cookie", map[string]string{"Cookie": value, "Authorization": "", "Sec-Fetch-Site": "same-origin"}, 401},
		{"duplicate cookies", map[string]string{"Cookie": value + "; " + value, "Sec-Fetch-Site": "same-origin"}, 401},
		{"key replaces bad cookie", map[string]string{"Cookie": cookie.Name + "=bad", "Authorization": "Bearer admin"}, 200},
		{"Bearer session rejected", map[string]string{"Authorization": "Bearer " + cookie.Value}, 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := sessionRequest(t, h, "GET", "/api/selectors", "", test.headers)
			if w.Code != test.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	for _, header := range []string{"Origin", "X-Dae-API"} {
		headers := map[string]string{"Cookie": value, "Origin": "https://192.0.2.1:9080", "X-Dae-API": "1"}
		delete(headers, header)
		if w := sessionRequest(t, h, "DELETE", "/api/selectors/proxy", "", headers); w.Code != 403 {
			t.Fatal("cookie mutation accepted without browser boundary", header, w.Code)
		}
	}
}

func TestSessionRejectsExpiredAndTamperedCookies(t *testing.T) {
	h := NewHandler(Options{AdminKey: "admin"})
	for _, expires := range []int64{time.Now().Unix() - 1, time.Now().Add(time.Hour).Unix()} {
		payload := "dae1.admin." + strconv.FormatInt(expires, 10) + ".nonce"
		token := payload + "." + base64.RawURLEncoding.EncodeToString(sessionSignature(payload, "192.0.2.1:9080", "admin"))
		if expires > time.Now().Unix() {
			token += "tampered"
		}
		if _, ok := h.sessionRole(token, "192.0.2.1:9080"); ok {
			t.Fatal("accepted expired or tampered cookie")
		}
	}
}

func TestStaleSessionCanBeClearedWithoutAKey(t *testing.T) {
	const origin = "https://192.0.2.1:8443"
	options := Options{AdminKey: "admin", Selectors: &sessionSelectors{}, AllowLANAnonymous: true, ResolveClient: verifiedTestLAN, WebOrigins: []string{origin}}
	cookie := loginCookie(t, NewHandler(options), "admin")
	options.AdminKey = ""
	h := NewHandler(options)
	headers := map[string]string{"Origin": origin, "Sec-Fetch-Site": "same-site", "Cookie": cookie.Name + "=" + cookie.Value}
	w := sessionRequest(t, h, "GET", "/api/selectors", "", headers)
	if w.Code != 401 || w.Header().Get("X-Dae-Session-Invalid") != "1" ||
		w.Header().Get("Access-Control-Expose-Headers") != "X-Dae-Session-Invalid" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("expired cookie must stay unauthorized and disclose only its invalidity", w.Code, w.Header())
	}
	headers["X-Dae-API"] = "1"
	w = sessionRequest(t, h, "DELETE", "/api/session", "", headers)
	cookies := w.Result().Cookies()
	if w.Code != 204 || len(cookies) != 1 || cookies[0].Name != cookie.Name || cookies[0].MaxAge != -1 {
		t.Fatal("explicit logout did not clear the stale cookie", w.Code, w.Header())
	}
	delete(headers, "Cookie")
	w = sessionRequest(t, h, "GET", "/api/selectors", "", headers)
	if w.Code != 200 || w.Header().Get("X-Dae-Session-Invalid") != "" {
		t.Fatal("anonymous LAN access did not recover", w.Code, w.Header())
	}
}
