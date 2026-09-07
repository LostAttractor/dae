// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnavailableWithoutHandler(t *testing.T) {
	server := &Server{}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestUnixListenerPreservesLiveSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	server, err := Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	second, err := Listen("unix", socketPath)
	if second != nil {
		defer second.Close()
	}
	if err == nil {
		t.Fatal("starting a second status server unexpectedly succeeded")
	}

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("original status socket became unreachable: %v", err)
	}
	_ = conn.Close()
}

func TestUnixListenerReplacesStaleSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err = stale.Close(); err != nil {
		t.Fatal(err)
	}

	server, err := Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("replacement status socket is unreachable: %v", err)
	}
	_ = conn.Close()
}

func TestUnixListenerPreservesNonSocketPath(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	want := []byte("do not remove")
	if err := os.WriteFile(socketPath, want, 0600); err != nil {
		t.Fatal(err)
	}

	server, err := Listen("unix", socketPath)
	if server != nil {
		defer server.Close()
	}
	if err == nil {
		t.Fatal("starting on a non-socket path unexpectedly succeeded")
	}
	got, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		t.Fatalf("occupied path was removed: %v", readErr)
	}
	if string(got) != string(want) {
		t.Fatalf("occupied path contents = %q, want %q", got, want)
	}
}

func TestCloseDoesNotRemoveReplacementSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.sock")
	first, err := Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	first.Close()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("old listener removed the replacement: %v", err)
	}
	_ = conn.Close()
}

func TestReloadDrainsBothTransports(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "unix" {
				address = filepath.Join(t.TempDir(), "dae.sock")
			}
			server, err := Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Addr().String())
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			check := func(code int) {
				t.Helper()
				r, err := client.Get("http://localhost/api/status")
				if err != nil {
					t.Fatal(err)
				}
				defer r.Body.Close()
				if r.StatusCode != code {
					t.Fatalf("response=%d want=%d", r.StatusCode, code)
				}
			}
			check(503)
			started, release := make(chan struct{}), make(chan struct{})
			server.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; w.WriteHeader(204) }))
			done := make(chan error, 1)
			go func() {
				r, err := client.Get("http://localhost/api/status")
				if err == nil {
					r.Body.Close()
					if r.StatusCode != 204 {
						err = fmt.Errorf("old response=%d", r.StatusCode)
					}
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("request never started")
			}
			switched := make(chan struct{})
			go func() { server.SetHandler(nil); close(switched) }()
			select {
			case <-switched:
				close(release)
				t.Fatal("retired handler with an active request")
			case <-time.After(25 * time.Millisecond):
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			select {
			case <-switched:
			case <-time.After(time.Second):
				t.Fatal("reload stayed blocked")
			}
			check(503)
			server.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
			check(200)
		})
	}
}
