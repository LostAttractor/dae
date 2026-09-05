// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestAPIServerReloadAndPortChanges(t *testing.T) {
	port := freeLocalPort(t)
	server, err := prepareAPIServer(nil, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	check := func(s *apiServer, code int, want string) {
		t.Helper()
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/device", s.port))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != code || (want != "" && string(body) != want) {
			t.Fatalf("response = %d %q, %v; want %d %q", response.StatusCode, body, err, code, want)
		}
	}
	handler := func(body string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
	}
	check(server, http.StatusServiceUnavailable, "")
	server.setHandler(handler("old CA and settings"))

	// Building a candidate must not change the active page or its settings.
	same, err := prepareAPIServer(server, port)
	if err != nil || same != server {
		t.Fatalf("unchanged port replaced listener: %v", err)
	}
	check(server, http.StatusOK, "old CA and settings")
	server.setHandler(nil)
	check(server, http.StatusServiceUnavailable, "")
	same.setHandler(handler("new CA and settings"))
	check(server, http.StatusOK, "new CA and settings")

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port = uint16(occupied.Addr().(*net.TCPAddr).Port)
	if _, err := prepareAPIServer(server, port); err == nil {
		t.Fatal("occupied port accepted")
	}
	check(server, http.StatusOK, "new CA and settings")

	port = freeLocalPort(t)
	next, err := prepareAPIServer(server, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	check(next, http.StatusServiceUnavailable, "")
	check(server, http.StatusOK, "new CA and settings")
	server.Close()
	next.setHandler(handler("changed port"))
	check(next, http.StatusOK, "changed port")

	if result, err := prepareAPIServer(next, 0); result != nil || err != nil {
		t.Fatalf("disabled server = %v, %v", result, err)
	}
	next.Close()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", next.port), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("closed portal still accepts connections")
	}
}

func TestAPIServerDrainsOldHandlerBeforeReload(t *testing.T) {
	server, err := prepareAPIServer(nil, freeLocalPort(t))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	started, release := make(chan struct{}), make(chan struct{})
	server.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "saved")
	}))
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	requestDone := make(chan error, 1)
	go func() {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/device", server.port))
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("request did not reach old handler")
	}
	switched := make(chan struct{})
	go func() {
		server.setHandler(nil)
		close(switched)
	}()
	select {
	case <-switched:
		close(release)
		t.Fatal("old control plane released while a request was still using it")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-switched:
	case <-time.After(time.Second):
		t.Fatal("handler switch did not complete")
	}
}
