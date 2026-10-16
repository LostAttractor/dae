// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/ca"
)

func TestCertificateChallengeRequiresFreshHandshake(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "ca.pem"), filepath.Join(directory, "ca.key")
	if err := ca.Generate(certPath, keyPath, "test CA", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := authority.ServerCertificate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.ReadCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	configuration := &tls.Config{RootCAs: roots}
	server, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := NewHandler(Options{Certificates: &Certificates{Identity: authority.Identity(), Handler: authority.Handler()}})
	certificateDirectory := t.TempDir()
	server.Configure(handler, authority, certificateDirectory)
	address := server.Addr().String()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: configuration}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	request := func(method, scheme, path, origin string, status int) []byte {
		t.Helper()
		r, _ := http.NewRequestWithContext(t.Context(), method, scheme+"://"+address+path, nil)
		if method == "POST" {
			r.Header.Set("X-Dae-API", "1")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			t.Fatalf("%s %s: %d, want %d: %s", method, path, response.StatusCode, status, body)
		}
		if status == 200 && origin != "" && response.Header.Get("Access-Control-Allow-Origin") != origin {
			t.Fatal("missing bootstrap CORS")
		}
		return body
	}
	start := func() api.CertificateTest {
		t.Helper()
		var test api.CertificateTest
		if err := json.Unmarshal(request("POST", "http", "/api/certificate/tests", "", 201), &test); err != nil {
			t.Fatal(err)
		}
		return test
	}
	old, err := tls.Dial("tcp", address, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	old.SetDeadline(time.Now().Add(5 * time.Second))
	oldLeaf := old.ConnectionState().PeerCertificates[0].Raw
	first, second := start(), start()
	if first.ID == second.ID || first.CAFingerprint != authority.Fingerprint() {
		t.Fatal("invalid challenge identity")
	}
	if cached, _ := authority.ServerCertificate("127.0.0.1"); shared != cached {
		t.Fatal("API test modified the MITM signing cache")
	}
	// Old connections remain useful for management, but never for trust proof.
	fmt.Fprintf(old, "GET /api/certificate HTTP/1.1\r\nHost: %s\r\n\r\n", address)
	metadata, err := http.ReadResponse(bufio.NewReader(old), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, metadata.Body)
	metadata.Body.Close()
	if metadata.StatusCode != 200 {
		t.Fatal("test disrupted ordinary requests")
	}
	fmt.Fprintf(old, "GET /api/certificate/tests/%s HTTP/1.1\r\nHost: %s\r\nOrigin: http://%s\r\nSec-Fetch-Site: cross-site\r\n\r\n", first.ID, address, address)
	stale, err := http.ReadResponse(bufio.NewReader(old), nil)
	if err != nil {
		t.Fatal(err)
	}
	stale.Body.Close()
	if stale.StatusCode != 409 || !stale.Close {
		t.Fatal("old handshake accepted as CA trust proof")
	}
	fresh, err := tls.Dial("tcp", address, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldLeaf, fresh.ConnectionState().PeerCertificates[0].Raw) {
		t.Fatal("test reused the old server certificate")
	}
	fresh.Close()
	other, err := tls.DialWithDialer(&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}, "tcp", address, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldLeaf, other.ConnectionState().PeerCertificates[0].Raw) {
		t.Error("challenge changed another client's management certificate")
	}
	other.Close()
	// Reload drains the plane before publishing its replacement. Pending tests
	// and TLS state survive that pause when the CA and directory stay the same.
	server.SetHandler(nil)
	request("GET", "http", "/api/certificate", "", 503)
	request("GET", "https", "/api/certificate", "", 503)
	authority, err = ca.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	server.Configure(handler, authority, certificateDirectory)
	client.CloseIdleConnections()
	// Parallel tests can use the newest leaf, so another test cannot invalidate
	// a browser's in-flight proof. Both ids still require their own source/origin.
	// Complete the newest first; the older challenge must remain usable.
	for _, test := range []api.CertificateTest{second, first} {
		path := "/api/certificate/tests/" + test.ID
		request("GET", "http", path, "", 403)
		request("GET", "https", path, "", 403)
		request("GET", "https", path, "http://evil.example", 403)
		var proof api.CertificateTest
		if err := json.Unmarshal(request("GET", "https", path, "http://"+address, 200), &proof); err != nil || proof != test {
			t.Fatalf("proof: %+v, %v", proof, err)
		}
		request("GET", "https", path, "http://"+address, 404)
	}
	first, second = start(), start()
	identity := server.tls
	identity.mu.Lock()
	foreign := identity.tests[first.ID]
	foreign.source = netip.MustParseAddr("127.0.0.2")
	identity.tests[first.ID] = foreign
	expired := identity.tests[second.ID]
	expired.ExpiresAt = time.Now().Add(-time.Second)
	identity.tests[second.ID] = expired
	identity.mu.Unlock()
	request("GET", "https", "/api/certificate/tests/"+first.ID, "http://"+address, 404)
	request("GET", "https", "/api/certificate/tests/"+second.ID, "http://"+address, 404)
	identity.mu.Lock()
	for n := range maxCertificateTests {
		identity.tests[fmt.Sprint(n)] = certificateTest{ExpiresAt: time.Now().Add(time.Minute)}
	}
	identity.mu.Unlock()
	request("POST", "http", "/api/certificate/tests", "", 429)
}

func TestAPICertificateSurvivesRestartAndChallenge(t *testing.T) {
	caDirectory := filepath.Join(t.TempDir(), "pki")
	certificateDirectory := t.TempDir()
	var server *Server
	var authority *ca.Authority
	address := "127.0.0.1:0"
	restart := func() {
		t.Helper()
		if server != nil {
			server.Close()
		}
		var err error
		authority, err = ca.Ensure(caDirectory)
		if err != nil {
			t.Fatal(err)
		}
		server, err = Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		address = server.Addr().String()
		server.Configure(NewHandler(Options{Certificates: &Certificates{Identity: authority.Identity(), Handler: authority.Handler()}}), authority, certificateDirectory)
	}
	restart()
	t.Cleanup(func() { server.Close() })
	root, err := ca.ReadCertificate(filepath.Join(caDirectory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leaf := func() *x509.Certificate {
		t.Helper()
		connection, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		return connection.ConnectionState().PeerCertificates[0]
	}
	first := leaf()
	restart()
	if !bytes.Equal(first.Raw, leaf().Raw) {
		t.Fatal("ordinary restart replaced the HTTPS leaf")
	}
	files, err := filepath.Glob(filepath.Join(certificateDirectory, "*", "127.0.0.1.pem"))
	if err != nil || len(files) != 1 {
		t.Fatalf("stored leaves: %v, %v", files, err)
	}
	stored, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func() {
		t.Helper()
		current, err := os.ReadFile(files[0])
		if err != nil || !bytes.Equal(stored, current) {
			t.Fatal("challenge changed the persistent management identity", err)
		}
		currentInfo, err := os.Stat(files[0])
		if err != nil || !info.ModTime().Equal(currentInfo.ModTime()) {
			t.Fatal("challenge rewrote the management certificate file", err)
		}
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: time.Second}
	t.Cleanup(client.CloseIdleConnections)
	start := func() api.CertificateTest {
		t.Helper()
		request, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+address+"/api/certificate/tests", nil)
		request.Header.Set("X-Dae-API", "1")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("start challenge: status %d", response.StatusCode)
		}
		var test api.CertificateTest
		if err := json.UnmarshalRead(response.Body, &test); err != nil {
			t.Fatal(err)
		}
		return test
	}
	for _, outcome := range []string{"completed", "expired", "restart"} {
		t.Run(outcome, func(t *testing.T) {
			test := start()
			temporary := leaf()
			if bytes.Equal(first.RawSubjectPublicKeyInfo, temporary.RawSubjectPublicKeyInfo) {
				t.Fatal("challenge reused a key with potential browser exceptions")
			}
			if remaining := time.Until(temporary.NotAfter); remaining <= 0 || remaining > certificateTestLeafLifetime {
				t.Fatalf("temporary certificate lifetime: %v", remaining)
			}
			for _, offset := range []time.Duration{-4 * time.Minute, 2 * time.Minute, 5 * time.Minute} {
				if _, err := temporary.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", CurrentTime: time.Now().Add(offset)}); err != nil {
					t.Fatalf("trusted challenge with client clock offset %v: %v", offset, err)
				}
			}
			unchanged()
			switch outcome {
			case "completed":
				request, _ := http.NewRequestWithContext(t.Context(), "GET", "https://"+address+"/api/certificate/tests/"+test.ID, nil)
				request.Header.Set("Origin", "http://"+address)
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("complete challenge: status %d", response.StatusCode)
				}
			case "expired":
				server.tls.mu.Lock()
				expired := server.tls.tests[test.ID]
				expired.ExpiresAt = time.Now().Add(-time.Second)
				server.tls.tests[test.ID] = expired
				server.tls.mu.Unlock()
			case "restart":
				restart()
			}
			// Expiry must restore the management leaf even without an HTTP request.
			if !bytes.Equal(first.Raw, leaf().Raw) {
				t.Fatal("finished challenge did not restore the management certificate")
			}
			unchanged()
			restart()
			if !bytes.Equal(first.Raw, leaf().Raw) {
				t.Fatal("restart replaced the persistent management certificate")
			}
		})
	}
}

func newCertificateTestServer(t *testing.T) (*Server, *tls.Config, string) {
	t.Helper()
	pki := filepath.Join(t.TempDir(), "pki")
	authority, err := ca.Ensure(pki)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.ReadCertificate(filepath.Join(pki, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	server, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	directory := t.TempDir()
	// Trust setup remains public even when administration requires a key.
	server.Configure(NewHandler(Options{APIKey: "configured-key", Certificates: &Certificates{Identity: authority.Identity(), Handler: authority.Handler()}}), authority, directory)
	return server, &tls.Config{RootCAs: roots}, directory
}

func TestCertificateChallengeSourceLimit(t *testing.T) {
	server, configuration, _ := newCertificateTestServer(t)
	request := func(source, method, path string, want int) api.CertificateTest {
		t.Helper()
		transport := &http.Transport{TLSClientConfig: configuration, DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}).DialContext}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		scheme := "http"
		if method == "GET" {
			scheme = "https"
		}
		r, _ := http.NewRequestWithContext(t.Context(), method, scheme+"://"+server.Addr().String()+path, nil)
		r.Header.Set("X-Dae-API", "1")
		r.Header.Set("Origin", "http://"+server.Addr().String())
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s %s from %s: status %d, want %d", method, path, source, response.StatusCode, want)
		}
		var test api.CertificateTest
		if want < 300 {
			if err := json.UnmarshalRead(response.Body, &test); err != nil {
				t.Fatal(err)
			}
		}
		return test
	}
	const path = "/api/certificate/tests"
	var first api.CertificateTest
	for range maxCertificateTestsPerSource {
		first = request("127.0.0.1", "POST", path, 201)
	}
	request("127.0.0.1", "POST", path, 429)
	second := request("127.0.0.2", "POST", path, 201)
	// Completing a challenge frees its source's slot immediately.
	request("127.0.0.1", "GET", path+"/"+first.ID, 200)
	request("127.0.0.1", "POST", path, 201)
	// Expiry also frees capacity; a source cannot hold it indefinitely.
	server.tls.mu.Lock()
	expired := server.tls.tests[second.ID]
	expired.ExpiresAt = time.Now().Add(-time.Second)
	server.tls.tests[second.ID] = expired
	server.tls.mu.Unlock()
	// Fill the remaining global slots through different real source addresses.
	for n := maxCertificateTestsPerSource; n < maxCertificateTests; n++ {
		request(fmt.Sprintf("127.0.0.%d", n/maxCertificateTestsPerSource+1), "POST", path, 201)
	}
	request("127.0.0.100", "POST", path, 429)
}

func TestCloseJoinsCertificatePersistence(t *testing.T) {
	server, configuration, directory := newCertificateTestServer(t)
	identity := server.tls
	// Hold the issuance lock at the point where a handshake can publish a file.
	identity.mu.Lock()
	unlock := sync.OnceFunc(identity.mu.Unlock)
	t.Cleanup(unlock)
	closed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while certificate persistence was still active")
	case <-time.After(20 * time.Millisecond):
	}
	leaf, err := identity.managementCertificate(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join certificate persistence")
	}
	next, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	next.Configure(nil, identity.authority, directory)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", next.Addr().String(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !bytes.Equal(leaf.Leaf.Raw, conn.ConnectionState().PeerCertificates[0].Raw) {
		t.Fatal("replacement listener did not reuse the completed publication")
	}
}

func TestRetiredTLSConfigRejectsDelayedHandshake(t *testing.T) {
	for _, retire := range []string{"close", "disable", "replace"} {
		t.Run(retire, func(t *testing.T) {
			server, configuration, directory := newCertificateTestServer(t)
			identity := server.tls
			selected, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			resume := sync.OnceFunc(func() { close(release) })
			t.Cleanup(resume)
			// Pause between choosing the identity and acquiring its issuance lock.
			// Configure must retire even configs already handed to crypto/tls.
			identity.config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				close(selected)
				<-release
				leaf, err := identity.getCertificate(hello)
				finished <- err
				return leaf, err
			}
			handshake := make(chan struct{})
			go func() {
				defer close(handshake)
				conn, _ := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Addr().String(), configuration)
				if conn != nil {
					conn.Close()
				}
			}()
			select {
			case <-selected:
			case <-time.After(time.Second):
				t.Fatal("handshake did not select TLS config")
			}
			switch retire {
			case "close":
				server.Close()
			case "disable":
				server.Configure(nil, nil, "")
			case "replace":
				server.Configure(nil, identity.authority, t.TempDir())
			}
			resume()
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("retired identity accepted a delayed handshake")
				}
			case <-time.After(time.Second):
				t.Fatal("delayed certificate callback did not finish")
			}
			<-handshake
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("retired identity published a certificate: %v, %v", entries, err)
			}
		})
	}
}
