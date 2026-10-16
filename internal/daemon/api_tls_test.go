// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestSharedAPIListenerPublishesCurrentCA(t *testing.T) {
	current, err := apiserver.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	port := uint16(current.Addr().(*net.TCPAddr).Port)
	makeAuthority := func(name string) (*localca.Authority, *http.Client) {
		t.Helper()
		dir := t.TempDir()
		cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
		if err := localca.Generate(cert, key, name, time.Hour); err != nil {
			t.Fatal(err)
		}
		authority, err := localca.Load(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		root, err := localca.ReadCertificate(cert)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 2 * time.Second}
		t.Cleanup(client.CloseIdleConnections)
		return authority, client
	}
	handler := func(authority *localca.Authority) http.Handler {
		return daemonAPIHandler(apiserver.NewHandler(apiserver.Options{
			APIKey:       "test-key",
			Status:       func() *api.StatusSnapshot { return &api.StatusSnapshot{} },
			Certificates: &apiserver.Certificates{Identity: authority.Identity(), Handler: authority.Handler()},
		}))
	}
	first, firstClient := makeAuthority("first")
	certificateDirectory := t.TempDir()
	next, err := prepareAPIServer(current, port)
	if err != nil || next != current {
		t.Fatalf("listener was not reused: %v", err)
	}
	next.Configure(handler(first), first, certificateDirectory)
	// An idle classifier cannot block either protocol.
	idle, err := net.Dial("tcp", current.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	plainClient := &http.Client{Timeout: time.Second}
	defer plainClient.CloseIdleConnections()
	check := func(client *http.Client, scheme, path, origin, key string, status int) *http.Response {
		t.Helper()
		r, _ := http.NewRequestWithContext(t.Context(), "GET", scheme+"://"+current.Addr().String()+path, nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		if response.StatusCode != status {
			t.Fatalf("%s %s: status %d, want %d", scheme, path, response.StatusCode, status)
		}
		return response
	}
	httpOrigin := "http://" + current.Addr().String()
	for _, scheme := range []string{"http", "https"} {
		check(firstClient, scheme, "/", "", "", 200)
		check(firstClient, scheme, "/ca.pem", "", "", 200)
		check(firstClient, scheme, "/api/status", "", "", 401)
		check(firstClient, scheme, "/api/status", "", "test-key", 200)
	}
	login, _ := http.NewRequestWithContext(t.Context(), "PUT", "https://"+current.Addr().String()+"/api/session", nil)
	login.Header.Set("Origin", "https://"+current.Addr().String())
	login.Header.Set("Sec-Fetch-Site", "same-origin")
	login.Header.Set("Authorization", "Bearer test-key")
	login.Header.Set("X-Dae-API", "1")
	session, err := firstClient.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	session.Body.Close()
	if session.StatusCode != http.StatusNoContent || len(session.Cookies()) != 1 || !session.Cookies()[0].Secure {
		t.Fatal("HTTPS login did not create a secure session")
	}
	login.Method, login.Body = "GET", nil
	login.URL.Path = "/api/status"
	login.Header.Del("Authorization")
	login.AddCookie(session.Cookies()[0])
	authenticated, err := firstClient.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	authenticated.Body.Close()
	if authenticated.StatusCode != http.StatusOK {
		t.Fatal("HTTPS session did not authorize API access")
	}
	proof := check(firstClient, "https", "/api/certificate", "", "", 200)
	var metadata api.Certificate
	if err := json.UnmarshalRead(proof.Body, &metadata); err != nil || metadata.Fingerprint != first.Fingerprint() {
		t.Fatalf("CA metadata: %+v, %v", metadata, err)
	}
	check(firstClient, "https", "/api/certificate", httpOrigin, "", 403)
	for _, path := range []string{"/api/status", "/api/device", "/api/device/mitm-tests/unknown"} {
		check(firstClient, "https", path, httpOrigin, "test-key", 403)
	}
	check(firstClient, "https", "/api/certificate", "http://evil.example", "", 403)
	check(firstClient, "https", "/test/removed", "", "", 404)
	// Untrusted roots cannot read even public HTTPS metadata.
	if response, err := plainClient.Get("https://" + current.Addr().String() + "/api/certificate"); err == nil {
		response.Body.Close()
		t.Fatal("untrusted CA accepted")
	}
	// A completed old-CA handshake must not serve new-CA metadata, even when
	// no HTTP request was sent before publication.
	preconnected, err := tls.Dial("tcp", current.Addr().String(), firstClient.Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer preconnected.Close()
	second, secondClient := makeAuthority("replacement")
	next.Configure(handler(first), nil, "")
	check(plainClient, "http", "/api/certificate", "", "", 200)
	firstClient.CloseIdleConnections()
	if response, err := firstClient.Get("https://" + current.Addr().String() + "/api/certificate"); err == nil {
		response.Body.Close()
		t.Fatal("HTTPS remained enabled")
	}
	next.Configure(handler(second), second, certificateDirectory)
	preconnected.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(preconnected, "GET /api/certificate HTTP/1.1\r\nHost: %s\r\n\r\n", current.Addr())
	stale, err := http.ReadResponse(bufio.NewReader(preconnected), nil)
	if err != nil {
		t.Fatal(err)
	}
	stale.Body.Close()
	if stale.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("old TLS handshake authenticated current CA metadata")
	}
	if response, err := firstClient.Get("https://" + current.Addr().String() + "/api/certificate"); err == nil {
		response.Body.Close()
		t.Fatal("old CA trusted replacement")
	}
	fresh := check(secondClient, "https", "/api/certificate", "", "", 200)
	if err := json.UnmarshalRead(fresh.Body, &metadata); err != nil || metadata.Fingerprint != second.Fingerprint() {
		t.Fatal("replacement CA not published")
	}
	// SNI cannot turn the API into a certificate issuer for arbitrary names.
	cfg := secondClient.Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.ServerName = "unrelated.example"
	if conn, err := tls.Dial("tcp", current.Addr().String(), cfg); err == nil {
		conn.Close()
		t.Fatal("unrelated SNI accepted")
	}
	// A failed port reservation preserves the accepted listener.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := prepareAPIServer(current, uint16(busy.Addr().(*net.TCPAddr).Port)); err == nil {
		t.Fatal("occupied port accepted")
	}
	io.Copy(io.Discard, check(secondClient, "https", "/api/status", "", "test-key", 200).Body)
	current.Close()
	idle.SetReadDeadline(time.Now().Add(time.Second))
	_, err = idle.Read(make([]byte, 1))
	if timeout, ok := errors.AsType[net.Error](err); err == nil || ok && timeout.Timeout() {
		t.Fatal("idle classifier survived closure")
	}
}
