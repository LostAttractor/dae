// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
)

func TestWorkerClientUsesCurrentRoutingBeforePoolLookup(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "first") }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "second") }))
	defer second.Close()
	dial := func(address string) downloadTestDialer {
		return func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, address)
		}
	}
	direct := downloadTestGroup(t, "direct", dial(first.Listener.Addr().String()))
	block := downloadTestGroup(t, "block", dial(first.Listener.Addr().String()))
	proxy := downloadTestGroup(t, "proxy", dial(second.Listener.Addr().String()))
	old := downloadTestPlane(t, "", direct, block, proxy)
	next := downloadTestPlane(t, "dip(192.0.2.10) -> proxy", direct, block, proxy)
	runtime := NewRuntime()
	client, closeClient := runtime.NewWorkerClient()
	defer closeClient()
	runtime.mu.Lock()
	runtime.current = old
	runtime.mu.Unlock()
	request := func(want string) {
		t.Helper()
		response, err := client.Get("http://192.0.2.10/")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != want {
			t.Fatalf("response = %q, %v; want %q", body, err, want)
		}
	}
	request("first")
	runtime.mu.Lock()
	runtime.current = next
	runtime.mu.Unlock()
	request("second")
	old.workerRoundTrips.Wait()
	next.workerRoundTrips.Wait()
}

func TestWorkerResponseOutlivesRetiredPlane(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()
		finish := make(chan struct{})
		group := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		})
		plane := downloadTestPlane(t, "", group)
		runtime := NewRuntime()
		runtime.current = plane
		client, closeClient := runtime.NewWorkerClient()
		defer closeClient()
		go func() {
			buffer := make([]byte, 4096)
			_, _ = peer.Read(buffer)
			_, _ = io.WriteString(peer, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
			<-finish
			_, _ = io.WriteString(peer, "body")
		}()
		response, err := client.Get("http://192.0.2.10/")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		runtime.mu.Lock()
		runtime.current = nil
		runtime.mu.Unlock()
		retired := make(chan struct{})
		go func() {
			plane.workerRoundTrips.Wait()
			_ = group.Close()
			close(retired)
		}()
		synctest.Wait()
		select {
		case <-retired:
		default:
			t.Error("retirement still waits for the response body")
		}
		close(finish)
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != "body" {
			t.Fatalf("retired path lost its established response: %q, %v", body, err)
		}
	})
}
