// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	mitmca "github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/certtest"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestSharedAPIListenerPublishesCurrentCA(t *testing.T) {
	current, err := apiserver.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	port := uint16(current.Addr().(*net.TCPAddr).Port)
	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("TLS reached administrative HTTP handler")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	targets, err := certtest.ParseTargets("", "")
	if err != nil {
		t.Fatal(err)
	}
	addresses := []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}}
	makeService := func(name string) (*certtest.Service, *http.Client) {
		t.Helper()
		dir := t.TempDir()
		cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
		if err := mitmca.Generate(cert, key, name, time.Hour); err != nil {
			t.Fatal(err)
		}
		authority, err := mitmca.Load(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		root, err := mitmca.ReadCertificate(cert)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 2 * time.Second}
		t.Cleanup(client.CloseIdleConnections)
		service, err := certtest.New(authority, port, targets, addresses)
		if err != nil {
			t.Fatal(err)
		}
		return service, client
	}
	first, firstClient := makeService("first")
	next, err := prepareAPIServer(current, port)
	if err != nil || next != current {
		t.Fatalf("listener reservation was not reused: %v", err)
	}
	next.SetHandlers(plain, certtest.Endpoint{Service: first})
	// An idle classifier must not block HTTP or TLS on the shared listener.
	idle, err := net.Dial("tcp", current.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	plainClient := &http.Client{Timeout: time.Second}
	defer plainClient.CloseIdleConnections()
	checkHTTP := func() {
		t.Helper()
		response, err := plainClient.Get("http://" + current.Addr().String() + "/api/status")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("HTTP status: %d", response.StatusCode)
		}
	}
	checkHTTP()
	ip, mac := netip.MustParseAddr("127.0.0.1"), [6]byte{2, 1}
	request := func(service *certtest.Service, client *http.Client, wantSuccess bool) {
		t.Helper()
		test, err := service.Start(ip, mac, netip.AddrPortFrom(ip, port), true)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := http.NewRequestWithContext(t.Context(), "GET", test.TrustURL, nil)
		r.Header.Set("Origin", "http://"+current.Addr().String())
		response, err := client.Do(r)
		if err != nil {
			if wantSuccess {
				t.Fatal(err)
			}
			return
		}
		response.Body.Close()
		if !wantSuccess || response.StatusCode != 200 {
			t.Fatalf("unexpected TLS response: %d", response.StatusCode)
		}
	}
	request(first, firstClient, true)
	// A completed old-CA handshake must not answer a new-CA challenge after
	// publication, even if the browser opened the socket before sending HTTP.
	preconnected, err := tls.Dial("tcp", current.Addr().String(), firstClient.Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer preconnected.Close()
	second, secondClient := makeService("replacement")
	next.SetHandlers(plain, nil)
	request(first, firstClient, false)
	checkHTTP()
	next.SetHandlers(plain, certtest.Endpoint{Service: second})
	fresh, err := second.Start(ip, mac, netip.AddrPortFrom(ip, port), true)
	if err != nil {
		t.Fatal(err)
	}
	preconnected.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(preconnected, "GET /test/%s HTTP/1.1\r\nHost: %s\r\nOrigin: http://%s\r\n\r\n", fresh.ID, current.Addr(), current.Addr())
	stale, err := http.ReadResponse(bufio.NewReader(preconnected), nil)
	if err != nil {
		t.Fatal(err)
	}
	stale.Body.Close()
	if stale.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("old TLS handshake produced a current-CA witness")
	}
	request(second, firstClient, false)
	request(second, secondClient, true)
	response, err := secondClient.Get("https://" + current.Addr().String() + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("HTTPS exposed the administrative API")
	}
	// A rejected replacement must not close an already accepted listener.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := prepareAPIServer(current, uint16(busy.Addr().(*net.TCPAddr).Port)); err == nil {
		t.Fatal("accepted an occupied API port")
	}
	request(second, secondClient, true)
	checkHTTP()
	current.Close()
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	_, err = idle.Read(make([]byte, 1))
	if timeout, ok := errors.AsType[net.Error](err); err == nil || ok && timeout.Timeout() {
		t.Fatal("idle classifier survived listener closure")
	}
}
