// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

type sessionSelectors struct {
	state api.SelectorState
}

func (s *sessionSelectors) Selectors() []api.SelectorState {
	return []api.SelectorState{s.state}
}

func (s *sessionSelectors) Select(group, node, _ string) (api.SelectorState, error) {
	s.state = api.SelectorState{Name: group, NodeID: node}
	return s.state, nil
}

func rejectLANClient(netip.AddrPort, netip.AddrPort) ([6]byte, error) {
	return [6]byte{}, net.ErrClosed
}

func TestBrowserSessionLoginPersistenceAndLogout(t *testing.T) {
	store := &sessionSelectors{state: api.SelectorState{Name: "private-group"}}
	server := httptest.NewServer(NewHandler(Options{
		APIKey: "private-api-key", Selectors: store,
		Status: func() *api.StatusSnapshot { return &api.StatusSnapshot{} },
	}))
	defer server.Close()
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	request := func(method, path, key, body string, want int) []*http.Cookie {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Dae-API", "1")
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s %s: got %d, want %d", method, path, response.StatusCode, want)
		}
		cookies := response.Cookies()
		if response.StatusCode >= 400 && len(cookies) != 0 {
			t.Fatalf("rejected %s %s changed session cookies: %v", method, path, cookies)
		}
		return cookies
	}
	request("GET", "/api/selectors", "", "", 401)
	request("PUT", "/api/session", "wrong", "", 401)
	request("GET", "/api/selectors", "", "", 401)
	cookies := request("PUT", "/api/session", "private-api-key", "", 204)
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %v", cookies)
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api" || cookie.Domain != "" || cookie.MaxAge != int(sessionLifetime.Seconds()) || strings.Contains(cookie.Value, "private-api-key") {
		t.Fatalf("unexpected session cookie: %+v", cookie)
	}
	// Subsequent page loads and mutations authenticate using only the cookie.
	request("GET", "/api/selectors", "", "", 200)
	request("GET", "/api/status", "", "", 200)
	// A saved session grants administration, but cannot renew itself without the key.
	request("PUT", "/api/session", "", "", 401)
	request("PUT", "/api/session", "wrong", "", 401)
	request("PUT", "/api/selectors/private-group", "", `{"node_id":"second"}`, 200)
	request("GET", "/api/selectors", "wrong", "", 401)
	request("DELETE", "/api/selectors/private-group", "", "", 200)
	logout := request("DELETE", "/api/session", "", "", 204)
	if len(logout) != 1 || logout[0].MaxAge != -1 || logout[0].Path != cookie.Path {
		t.Fatalf("logout did not clear the session: %v", logout)
	}
	request("GET", "/api/selectors", "", "", 401)
	request("GET", "/api/status", "", "", 401)
	request("GET", "/api/selectors", "private-api-key", "", 200)
}

func sessionRequest(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "http://192.0.2.1:9080"+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.10:45000"
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}))
	for key, value := range headers {
		if value != "" {
			r.Header.Set(key, value)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestSessionRejectsExpiredTamperedAndRotatedCredentials(t *testing.T) {
	options := Options{APIKey: "secret", Selectors: &sessionSelectors{state: api.SelectorState{Name: "private-group"}}, ResolveClient: rejectLANClient}
	login := sessionRequest(t, NewHandler(options), "PUT", "/api/session", "", map[string]string{"Authorization": "Bearer secret", "X-Dae-API": "1"})
	if login.Code != 204 {
		t.Fatal(login.Code, login.Body.String())
	}
	valid := login.Result().Cookies()[0].Value
	signed := func(deadline time.Time, host string) string {
		payload := strconv.FormatInt(deadline.Unix(), 10) + ".nonce"
		signer := &handler{options: options}
		return payload + "." + base64.RawURLEncoding.EncodeToString(signer.sessionSignature(payload, host))
	}
	for _, test := range []struct {
		name, key, cookie string
		want              int
	}{
		{"reload with same key", "secret", valid, 200},
		{"missing session", "secret", "", 401},
		{"API key is not a session", "secret", "secret", 401},
		{"tampered", "secret", valid + "x", 401},
		{"expired", "secret", signed(time.Now().Add(-time.Minute), "192.0.2.1:9080"), 401},
		{"other listener", "secret", signed(time.Now().Add(time.Hour), "192.0.2.1:9081"), 401},
		{"rotated key", "new-secret", valid, 401},
		{"removed key without LAN identity", "", valid, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			updated := options
			updated.APIKey = test.key
			w := sessionRequest(t, NewHandler(updated), "GET", "/api/selectors", "", map[string]string{"Cookie": sessionCookieName + "=" + test.cookie})
			if w.Code != test.want || (w.Code != 200 && strings.Contains(w.Body.String(), "private-group")) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestKeylessAdministrationRequiresCurrentLANIdentity(t *testing.T) {
	store := &sessionSelectors{state: api.SelectorState{Name: "private-group"}}
	allowed := true
	options := Options{
		Selectors: store,
		Status:    func() *api.StatusSnapshot { return &api.StatusSnapshot{Version: "private-status"} },
		ResolveClient: func(source, destination netip.AddrPort) ([6]byte, error) {
			if source != netip.MustParseAddrPort("192.0.2.10:45000") || netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port()) != netip.MustParseAddrPort("192.0.2.1:9080") {
				t.Errorf("used untrusted connection identity: %v -> %v", source, destination)
				return [6]byte{}, net.ErrClosed
			}
			if !allowed {
				return [6]byte{}, net.ErrClosed
			}
			return [6]byte{2, 0, 0, 0, 0, 10}, nil
		},
	}
	handler := NewHandler(options)
	headers := map[string]string{
		"X-Dae-API": "1", "Content-Type": "application/json",
		"X-Forwarded-For": "127.0.0.1", "X-Dae-Local": "1",
		"Authorization": "Bearer old-key", "Cookie": sessionCookieName + "=old-session",
	}
	for _, operation := range []struct{ method, path, body string }{
		{"GET", "/api/status", ""},
		{"GET", "/api/selectors", ""},
		{"PUT", "/api/selectors/private-group", `{"node_id":"second"}`},
		{"DELETE", "/api/selectors/private-group", ""},
		{"PUT", "/api/session", ""},
	} {
		t.Run(operation.method+operation.path, func(t *testing.T) {
			allowed = true
			w := sessionRequest(t, handler, operation.method, operation.path, operation.body, headers)
			want := 200
			if operation.path == "/api/session" {
				want = 204
				cookies := w.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Value != "" || cookies[0].MaxAge != -1 {
					t.Fatal("keyless LAN login did not clear the saved session")
				}
			}
			if w.Code != want {
				t.Fatalf("LAN request: status=%d body=%s", w.Code, w.Body.String())
			}
			if operation.path == "/api/selectors" {
				var data api.SelectorsResponse
				if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || !data.AdminEnabled || data.AuthMode != "lan" {
					t.Fatalf("LAN authentication mode: %+v, %v", data, err)
				}
			}
			// A previously accepted connection must be rejected once its LAN
			// observation/neighbor identity is no longer valid, even with credentials.
			allowed = false
			state := store.state
			w = sessionRequest(t, handler, operation.method, operation.path, operation.body, headers)
			if w.Code != 403 || strings.Contains(w.Body.String(), "private-") || store.state.NodeID != state.NodeID || len(w.Result().Cookies()) != 0 {
				t.Fatalf("non-LAN request: status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	// Enabling a key immediately requires credentials even for a verified LAN peer.
	options.APIKey = "new-key"
	handler = NewHandler(options)
	allowed = true
	for _, key := range []string{"", "old-key", "new-key"} {
		w := sessionRequest(t, handler, "GET", "/api/selectors", "", map[string]string{"Authorization": "Bearer " + key})
		want := 401
		if key == "new-key" {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("configured key: status=%d, want %d", w.Code, want)
		}
	}
	// Key authentication does not depend on LAN identity.
	allowed = false
	w := sessionRequest(t, handler, "GET", "/api/selectors", "", map[string]string{"Authorization": "Bearer new-key"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestKeylessAdministrationRejectsBrowserRequestBypasses(t *testing.T) {
	for _, headers := range []map[string]string{
		{"Origin": "http://evil.example", "X-Dae-API": "1"},
		{"Sec-Fetch-Site": "cross-site", "X-Dae-API": "1"},
		{},
	} {
		options := Options{ResolveClient: func(netip.AddrPort, netip.AddrPort) ([6]byte, error) {
			t.Fatal("invalid browser request reached LAN identity resolution")
			return [6]byte{}, nil
		}}
		w := sessionRequest(t, NewHandler(options), "PUT", "/api/selectors/private-group", `{"node_id":"second"}`, headers)
		if w.Code != 403 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestUnixAdministrationUsesSocketPermissions(t *testing.T) {
	for _, key := range []string{"", "configured-key"} {
		t.Run(key, func(t *testing.T) {
			handler := NewHandler(Options{APIKey: key, Selectors: &sessionSelectors{}})
			request := func(method, path string) *httptest.ResponseRecorder {
				r := httptest.NewRequestWithContext(t.Context(), method, "http://unix"+path, nil)
				r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "dae.sock", Net: "unix"}))
				r.Header.Set("X-Dae-API", "1")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			w := request("GET", "/api/selectors")
			var data api.SelectorsResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || data.AuthMode != "unix" {
				t.Fatal(w.Code, w.Body.String())
			}
			// Local administration is not permission to mint a browser session
			// without supplying the configured API key.
			want := 204
			if key != "" {
				want = 401
			}
			if w := request("PUT", "/api/session"); w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestSessionRequiresSameOriginAndMutationHeader(t *testing.T) {
	for _, method := range []string{"PUT", "DELETE"} {
		for _, test := range []struct {
			name, origin, site, marker, body string
			want                             int
		}{
			{name: "missing marker", want: 403},
			{name: "foreign origin", marker: "1", origin: "http://evil.example", want: 403},
			{name: "cross-site metadata", marker: "1", site: "cross-site", want: 403},
			{name: "unexpected body", marker: "1", body: "{}", want: 400},
			{name: "valid", marker: "1", origin: "http://192.0.2.1:9080", site: "same-origin", want: 204},
		} {
			t.Run(method+"/"+test.name, func(t *testing.T) {
				w := sessionRequest(t, NewHandler(Options{APIKey: "secret"}), method, "/api/session", test.body, map[string]string{
					"Authorization": "Bearer secret", "X-Dae-API": test.marker, "Origin": test.origin, "Sec-Fetch-Site": test.site,
				})
				if w.Code != test.want || (w.Code != 204 && len(w.Result().Cookies()) != 0) {
					t.Fatalf("status=%d cookies=%v", w.Code, w.Result().Cookies())
				}
			})
		}
	}
}
