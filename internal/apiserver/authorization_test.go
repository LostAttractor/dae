// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

func verifiedTestLAN(netip.AddrPort, netip.AddrPort) (api.ClientIdentity, error) {
	return api.ClientIdentity{LinkType: "ethernet", MAC: [6]byte{2, 0, 0, 0, 0, 1}}, nil
}
func accessRequest(t *testing.T, h http.Handler, method, path, key, origin string, tls, local bool) *httptest.ResponseRecorder {
	t.Helper()
	scheme := "http"
	if tls {
		scheme = "https"
	}
	r := httptest.NewRequest(method, scheme+"://192.0.2.1:9080"+path, nil)
	r.RemoteAddr = "192.0.2.2:12345"
	var addr net.Addr = &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}
	if local {
		addr = &net.UnixAddr{Net: "unix", Name: "dae.sock"}
	}
	r = r.WithContext(context.WithValue(t.Context(), http.LocalAddrContextKey, addr))
	if key != "" {
		r.Header.Set("Authorization", key)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.Header.Set("X-Dae-API", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestPprofSymbolPost(t *testing.T) {
	h := NewHandler(Options{Pprof: true, UserKey: "user", AdminKey: "admin"})
	for key, want := range map[string]int{"Bearer user": http.StatusForbidden, "Bearer admin": http.StatusOK} {
		w := accessRequest(t, h, http.MethodPost, "/debug/pprof/symbol", key, "", true, false)
		if w.Code != want || want == http.StatusOK && !strings.HasPrefix(w.Body.String(), "num_symbols: ") {
			t.Fatalf("symbol lookup: status=%d body=%q, want %d", w.Code, w.Body.String(), want)
		}
	}
}

func TestUserAdminAndLANWebBoundaries(t *testing.T) {
	options := Options{UserKey: "user", AdminKey: "admin", AllowLANAnonymous: true, WebOrigins: []string{"https://web.example"}, ResolveClient: verifiedTestLAN, Selectors: &sessionSelectors{}, Pprof: true, Metrics: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "metric 1\n") })}
	for _, test := range []struct {
		name, path, key, origin string
		tls, local              bool
		want                    int
	}{
		{name: "user metrics", path: "/metrics", key: "Bearer user", tls: true, want: 200},
		{name: "admin inherits user", path: "/metrics", key: "Bearer admin", tls: true, want: 200},
		{name: "LAN anonymous", path: "/metrics", tls: true, want: 200},
		{name: "LAN same origin", path: "/metrics", origin: "https://192.0.2.1:9080", tls: true, want: 200},
		{name: "LAN approved independent Web", path: "/metrics", origin: "https://web.example", tls: true, want: 200},
		{name: "LAN unapproved Web", path: "/metrics", origin: "https://other.example", want: 403},
		{name: "key does not bypass Web list", path: "/metrics", key: "Bearer user", origin: "https://other.example", tls: true, want: 403},
		{name: "key approved Web", path: "/metrics", key: "Bearer user", origin: "https://web.example", tls: true, want: 200},
		{name: "invalid key never falls back to LAN", path: "/metrics", key: "Bearer wrong", tls: true, want: 401},
		{name: "HTTP credentials rejected", path: "/metrics", key: "Bearer admin", want: 403},
		{name: "anonymous cannot profile", path: "/debug/pprof/heap", tls: true, want: 401},
		{name: "user cannot profile", path: "/debug/pprof/heap", key: "Bearer user", tls: true, want: 403},
		{name: "Basic profiling", path: "/debug/pprof/goroutine?debug=1", key: "Basic " + base64.StdEncoding.EncodeToString([]byte("dae:admin")), tls: true, want: 200},
		{name: "Basic limited to profiling", path: "/metrics", key: "Basic " + base64.StdEncoding.EncodeToString([]byte("dae:admin")), tls: true, want: 401},
		{name: "Unix bypasses keys", path: "/metrics", key: "Bearer wrong", local: true, want: 200},
		{name: "Unix rejects unapproved browser", path: "/metrics", origin: "https://other.example", local: true, want: 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := accessRequest(t, NewHandler(options), "GET", test.path, test.key, test.origin, test.tls, test.local)
			if w.Code != test.want {
				t.Fatal(w.Code, w.Body.String())
			}
			if test.want == 200 && test.origin != "" && !test.local && w.Header().Get("Access-Control-Allow-Origin") != test.origin {
				t.Fatal("missing CORS response")
			}
		})
	}
	for _, key := range []string{"", "Bearer user", "Bearer admin"} {
		w := accessRequest(t, NewHandler(options), "DELETE", "/api/selectors/proxy", key, "", true, false)
		want := 401
		if key == "Bearer user" {
			want = 403
		}
		if key == "Bearer admin" {
			want = 200
		}
		if w.Code != want {
			t.Fatal(key, w.Code, w.Body.String())
		}
	}
	options.AdminKey = ""
	if w := accessRequest(t, NewHandler(options), "DELETE", "/api/selectors/proxy", "", "", true, false); w.Code != 401 {
		t.Fatal("LAN granted admin without configured key")
	}
	if w := accessRequest(t, NewHandler(options), "DELETE", "/api/selectors/proxy", "", "", false, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	options.Pprof = false
	if w := accessRequest(t, NewHandler(options), "GET", "/debug/pprof/heap", "", "", false, true); w.Code != 404 {
		t.Fatal("disabled profiling remained exposed")
	}
}
func TestPreflightDoesNotAuthorizeCredentiallessRequests(t *testing.T) {
	h := NewHandler(Options{UserKey: "user", WebOrigins: []string{"https://web.example"}, Metrics: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })})
	for _, origin := range []string{"https://web.example", "https://other.example"} {
		for _, headers := range []string{"authorization", "x-dae-api"} {
			w := sessionRequest(t, h, "OPTIONS", "/metrics", "", map[string]string{"Origin": origin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": headers})
			want := 403
			if origin == "https://web.example" {
				want = 204
			}
			if w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
		}
	}
	if w := accessRequest(t, h, "GET", "/metrics", "", "https://web.example", true, false); w.Code != 401 || w.Header().Get("Access-Control-Allow-Origin") != "https://web.example" || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("preflight authorized request or authentication error was unreadable", w.Code, w.Header())
	}
}
func TestMonitoringDoesNotHoldControlPlaneDrain(t *testing.T) {
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := NewHandler(Options{AllowLANAnonymous: true, ResolveClient: verifiedTestLAN, Metrics: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(started); <-release })})
	server := &Server{handler: h, tls: new(apiTLSIdentity)}
	connection := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		generation := &tlsConnectionGeneration{identity: server.tls}
		server.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tlsGenerationKey{}, generation)))
	})
	defer func() { close(release); <-done }()
	go func() { defer close(done); accessRequest(t, connection, "GET", "/metrics", "", "", true, false) }()
	select {
	case <-started:
	case <-done:
		t.Fatal("request ended before reaching the metrics handler")
	case <-time.After(time.Second):
		t.Fatal("metrics handler did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	resume, err := server.Pause(ctx)
	if err != nil {
		t.Fatalf("metrics blocked plane pause: %v", err)
	}
	defer resume()
	drained := make(chan struct{})
	go func() { server.SetHandler(nil); close(drained) }()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("metrics blocked plane draining")
	}
	// Unix metrics stay available even while the plane is absent.
	server.SetLocalServices(LocalServices{Metrics: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "metric 2") })})
	if w := accessRequest(t, server, "GET", "/metrics", "", "", false, true); w.Code != 200 || !strings.Contains(w.Body.String(), "metric 2") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func activeCaptures(path string) int {
	profile := contentionProfiles[path]
	profile.mu.Lock()
	defer profile.mu.Unlock()
	return profile.active
}

func waitCaptures(t *testing.T, path string, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); activeCaptures(path) != want; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s captures = %d, want %d", path, activeCaptures(path), want)
		}
	}
}

func TestPprofRecordsContentionOnlyDuringCaptures(t *testing.T) {
	server, err := Listen("unix", filepath.Join(t.TempDir(), "dae.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		waitCaptures(t, "/debug/pprof/mutex", 0)
		waitCaptures(t, "/debug/pprof/block", 0)
	})
	server.SetHandler(NewHandler(Options{Pprof: true}))
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 0 {
		t.Fatalf("enabling pprof set the mutex fraction to %d", fraction)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", server.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	// Snapshots and completed delta captures must leave sampling disabled.
	for _, path := range []string{"/debug/pprof/block", "/debug/pprof/mutex", "/debug/pprof/mutex?seconds=1"} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %s", path, response.Status)
		}
		waitCaptures(t, "/debug/pprof/mutex", 0)
		waitCaptures(t, "/debug/pprof/block", 0)
		if fraction := runtime.SetMutexProfileFraction(-1); fraction != 0 {
			t.Fatalf("mutex fraction %d after %s", fraction, path)
		}
	}
	capture := func(path string) (context.CancelFunc, <-chan struct{}) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path+"?seconds=10", nil)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if response, err := client.Do(request); err == nil {
				_ = response.Body.Close()
			}
		}()
		return cancel, done
	}
	first, firstDone := capture("/debug/pprof/mutex")
	second, secondDone := capture("/debug/pprof/mutex")
	waitCaptures(t, "/debug/pprof/mutex", 2)
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 1 {
		t.Fatalf("capture recorded with mutex fraction %d", fraction)
	}
	// A client disconnect ends its capture; the overlapping one continues.
	first()
	<-firstDone
	waitCaptures(t, "/debug/pprof/mutex", 1)
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 1 {
		t.Fatal("an ended capture stopped another")
	}
	server.SetLocalServices(LocalServices{Pprof: true})
	_, blockDone := capture("/debug/pprof/block")
	waitCaptures(t, "/debug/pprof/block", 1)
	// Neither plane nor daemon handler replacement waits for a capture.
	drained := make(chan struct{})
	go func() {
		server.SetHandler(nil)
		server.SetLocalServices(LocalServices{})
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("profiling blocked handler replacement")
	}
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 1 {
		t.Fatal("handler replacement stopped an active capture")
	}
	// Closing the shared API server ends the remaining captures.
	server.Close()
	waitCaptures(t, "/debug/pprof/mutex", 0)
	waitCaptures(t, "/debug/pprof/block", 0)
	second()
	<-secondDone
	<-blockDone
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 0 {
		t.Fatalf("mutex fraction %d after the last capture", fraction)
	}
}
