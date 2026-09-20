// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

// Keep the client TLS connection fixed to example.com while sending a second
// :authority, as observed in the iOS trace. Each request must get the right
// middleware while retaining the original upstream TLS identity and connection.
func TestDomainFrontingAuthorities(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		for _, preserve := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/preserve_route=%t", protocol, preserve), func(t *testing.T) {
				testDomainFrontingAuthorities(t, protocol, preserve)
			})
		}
	}
}

func testDomainFrontingAuthorities(t *testing.T, protocol string, preserve bool) {
	authority, roots := http3TestAuthority(t)
	upstreamAuthority, upstreamRoots := http3TestAuthority(t)
	upstreamTLS := &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return upstreamAuthority.ServerCertificate(hello.ServerName)
	}}
	logger, _, ended := observationLogger()
	var mu sync.Mutex
	wraps, dials, plans := make(map[string]int), make(map[string]int), make(map[string]int)
	var instances []Instance
	for _, host := range []string{"example.com", "app.example"} {
		p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope(host), PreserveRoute: host == "example.com" && preserve}}}}
		p.wrap = func(flow plugin.Flow, next plugin.Handler) plugin.Handler {
			if flow.Host != host || !flow.Source.IsValid() || !flow.Destination.IsValid() {
				t.Errorf("incorrect middleware flow for %s: %+v", host, flow)
			}
			mu.Lock()
			wraps[host]++
			mu.Unlock()
			return func(e *plugin.Exchange) (*http.Response, error) {
				e.Request.Header.Add("X-Test-Scope", host)
				if e.Request.URL.Path == "/rewrite" {
					e.Request.URL.Host, e.Request.Host = "rewrite.example", "rewrite.example"
				} else if e.Request.URL.Path == "/pathrewrite" {
					e.Request.URL.Path, e.Request.URL.RawQuery = "/changed", "rewritten=true"
				}
				resp, err := next(e)
				if resp != nil {
					resp.Header.Set("X-Response-Scope", host)
				}
				return resp, err
			}
		}
		instances = append(instances, Instance{ID: host, Plugin: p})
	}
	wantProtocol := 2
	if protocol == "h3" {
		wantProtocol = 3
	}
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantName := "example.com"
		if r.URL.Path == "/rewrite" {
			wantName = "rewrite.example"
		}
		if r.TLS.ServerName != wantName || r.ProtoMajor != wantProtocol {
			t.Errorf("incorrect upstream identity/protocol: %s %s %s", r.Host, r.TLS.ServerName, r.Proto)
		}
		w.Header().Set("Alt-Svc", `h3="`+r.Host+`:443"`)
		fmt.Fprintf(w, "%s/%s/%s", r.TLS.ServerName, r.Host, strings.Join(r.Header.Values("X-Test-Scope"), ","))
	})
	var upstreamTCP string
	var upstreamUDP net.Addr
	if protocol == "h2" {
		upstream := httptest.NewUnstartedServer(upstreamHandler)
		upstream.EnableHTTP2 = true
		upstream.TLS = upstreamTLS
		upstream.StartTLS()
		t.Cleanup(upstream.Close)
		upstreamTCP = upstream.Listener.Addr().String()
	} else {
		upstreamUDP = http3TestUpstream(t, upstreamTLS, upstreamHandler)
	}
	host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: upstreamRoots}, Logger: logger}, instances...)
	planner := func(r *http.Request) (UpstreamPlan, error) {
		name := r.URL.Hostname()
		mu.Lock()
		plans[name]++
		mu.Unlock()
		recordDial := func(address string) {
			if address != net.JoinHostPort(name, "443") {
				t.Errorf("dialed stale authority: %s, want %s", address, name)
			}
			mu.Lock()
			dials[name]++
			mu.Unlock()
		}
		return UpstreamPlan{Key: name, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			recordDial(address)
			return (&net.Dialer{}).DialContext(ctx, network, upstreamTCP)
		}, DialPacket: func(_ context.Context, address string) (net.PacketConn, net.Addr, error) {
			recordDial(address)
			packets, err := net.ListenPacket("udp4", "127.0.0.1:0")
			return packets, upstreamUDP, err
		}}, nil
	}
	client := authorityTestClient(t, host, roots, protocol, planner)
	var connection string
	request := func(name, path, want string) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = name
		resp, err := client.Do(r)
		if err != nil {
			t.Error(err)
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		wantAltSvc := `h3=":443"`
		wantScope := name
		if name == "passport.example" {
			wantAltSvc, wantScope = `h3="passport.example:443"`, ""
		}
		if path == "/rewrite" {
			wantAltSvc = ""
		}
		if err != nil || resp.StatusCode != 200 || string(body) != want || resp.Header.Get("Alt-Svc") != wantAltSvc || resp.Header.Get("X-Response-Scope") != wantScope {
			t.Errorf("%s%s: status=%d body=%q Alt-Svc=%q err=%v", name, path, resp.StatusCode, body, resp.Header.Get("Alt-Svc"), err)
		}
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].VerifyHostname("passport.example") == nil {
			t.Error("expected a single-host downstream certificate")
		}
		entry := ended.next(t)
		mu.Lock()
		defer mu.Unlock()
		if connection == "" {
			connection = entry.Data["connection_id"].(string)
		}
		if connection == "" || entry.Data["connection_id"] != connection {
			t.Errorf("request did not reuse the same client connection: %v", entry.Data)
		}
	}
	request("example.com", "/", "example.com/example.com/example.com")
	request("app.example", "/", "example.com/app.example/app.example")
	request("app.example", "/pathrewrite", "example.com/app.example/app.example")
	request("passport.example", "/", "example.com/passport.example/")
	request("app.example", "/rewrite", "rewrite.example/rewrite.example/app.example")
	var requests sync.WaitGroup
	for i := range 8 {
		requests.Go(func() {
			if i%2 == 0 {
				request("app.example", "/", "example.com/app.example/app.example")
			} else {
				request("app.example", "/rewrite", "rewrite.example/rewrite.example/app.example")
			}
		})
	}
	requests.Wait()
	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"example.com", "app.example", "passport.example", "rewrite.example"} {
		wantWraps, wantDials := 0, 0
		if name == "example.com" || name == "app.example" {
			wantWraps = 1
		}
		if name == "example.com" || name == "rewrite.example" {
			wantDials = 1
		}
		if wraps[name] != wantWraps || dials[name] != wantDials {
			t.Errorf("%s: wraps=%d dials=%d, want %d/%d", name, wraps[name], dials[name], wantWraps, wantDials)
		}
	}
	if plans["example.com"] != 1 || plans["app.example"] != 0 || plans["passport.example"] != 0 {
		t.Fatalf("authority/path changes reselected the original route: %v", plans)
	}
}

func authorityTestClient(t *testing.T, host *Host, roots *x509.CertPool, protocol string, planner UpstreamPlanner) *http.Client {
	t.Helper()
	if protocol == "h2" {
		client, _ := tcpDrainClient(t, host, roots, protocol, planner)
		return client
	}
	intercepted, packets := http3TestPacketConn(t), http3TestPacketConn(t)
	flow := plugin.Flow{Host: "example.com", Port: 443,
		Source: netip.MustParseAddrPort(packets.LocalAddr().String()), Destination: netip.MustParseAddrPort(intercepted.LocalAddr().String())}
	served := make(chan error, 1)
	go func() { served <- host.ServePacketConn(intercepted, flow, planner, planner) }()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.Dial(ctx, packets, intercepted.LocalAddr(), cfg, qc)
		}}
	t.Cleanup(func() {
		_ = transport.Close()
		_ = host.Close()
		select {
		case err := <-served:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("HTTP/3 authority test failed to stop")
		}
	})
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func TestHTTPAuthorityAdmissionBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, scheme, authority, reason string
		protocol, status                int
	}{
		{"scoped H2", "https", "APP.EXAMPLE.:00443", "", 2, 200},
		{"outside scope covered", "https", "passport.example", "", 2, 200},
		{"excluded host covered", "https", "private.example", "", 2, 200},
		{"declared at different port covered", "https", "port.example", "", 2, 200},
		{"uncovered host", "https", "other.test", "", 2, 200},
		{"scoped but uncovered host", "https", "scope.test", "", 2, 200},
		{"nested host", "https", "nested.app.example", "", 2, 200},
		{"IP SAN", "https", "192.0.2.1", "", 2, 200},
		{"uncovered IP", "https", "192.0.2.2", "", 2, 200},
		{"different scoped port", "https", "port.example:8443", "authority_port_mismatch", 2, 421},
		{"same hostname different port", "https", "example.com:8443", "authority_port_mismatch", 2, 421},
		{"HTTP1 remains destination bound", "https", "app.example", "authority_mismatch", 1, 421},
		{"HTTP3 coalescing", "https", "app.example", "", 3, 200},
		{"cleartext remains destination bound", "http", "app.example", "authority_mismatch", 2, 421},
		{"invalid authority", "https", "user:secret@app.example/private?token=secret", "invalid_authority", 2, 421},
		{"empty authority", "https", "", "invalid_authority", 2, 421},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger, hook, ended := observationLogger()
			p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{
				{Host: "private.example", Ports: []uint16{443}, Exclude: true},
				{Host: "example.com", Ports: []uint16{80, 443}},
				{Host: "app.example", Ports: []uint16{80, 443}},
				{Host: "private.example", Ports: []uint16{443}},
				{Host: "port.example", Ports: []uint16{8443}},
				{Host: "scope.test", Ports: []uint16{443}},
			}}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler { return next }}
			h := testHost(t, Options{Authority: &mitmca.Authority{}, Logger: logger}, Instance{Plugin: p})
			port := uint16(443)
			if test.scheme == "http" {
				port = 80
			}
			called := false
			handler := h.handlerForFlow(test.scheme, plugin.Flow{Host: "example.com", Port: port}, roundTripFunc(func(*http.Request) (*http.Response, error) {
				called = true
				return response("ok"), nil
			}), http.DefaultClient)
			r := httptest.NewRequest(http.MethodGet, test.scheme+"://example.com/", nil)
			r.Host, r.ProtoMajor = test.authority, test.protocol
			r.Proto = fmt.Sprintf("HTTP/%d.0", test.protocol)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			entry := ended.next(t)
			if w.Code != test.status || called != (test.status == 200) {
				t.Fatalf("status=%d upstream=%t; want %d", w.Code, called, test.status)
			}
			if test.reason != "" && entry.Data["reason"] != test.reason {
				t.Fatalf("missing rejection reason: %v", entry.Data)
			}
			if entry.Data["connection_host"] != "example.com" || entry.Data["request_authority"] == "" {
				t.Fatalf("missing authority identities: %v", entry.Data)
			}
			if test.reason == "invalid_authority" {
				for _, entry := range hook.AllEntries() {
					text, _ := entry.String()
					if strings.Contains(text, "secret") || strings.Contains(text, "/private") {
						t.Fatalf("invalid authority leaked into logs: %s", text)
					}
				}
			}
		})
	}
}
