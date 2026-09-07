package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusServerReturnsUnavailableWithoutPublishedPlane(t *testing.T) {
	server := &StatusServer{version: "test"}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestStartStatusServerPreservesLiveSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	server, err := StartStatusServer(socketPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	second, err := StartStatusServer(socketPath, "test")
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

func TestStartStatusServerReplacesStaleSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err = stale.Close(); err != nil {
		t.Fatal(err)
	}

	server, err := StartStatusServer(socketPath, "test")
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

func TestStartStatusServerPreservesNonSocketPath(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	want := []byte("do not remove")
	if err := os.WriteFile(socketPath, want, 0600); err != nil {
		t.Fatal(err)
	}

	server, err := StartStatusServer(socketPath, "test")
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

func TestStatusPublishDrainsPreviousReaders(t *testing.T) {
	server := &StatusServer{version: "test"}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server.Publish(func(version string) *StatusSnapshot {
		close(entered)
		<-release
		return &StatusSnapshot{Version: version}
	})
	response := httptest.NewRecorder()
	go func() {
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		close(finished)
	}()
	<-entered
	publishing, drained := make(chan struct{}), make(chan struct{})
	go func() { close(publishing); server.Publish(nil); close(drained) }()
	<-publishing
	select {
	case <-drained:
		close(release)
		<-finished
		t.Fatal("publication returned while the old plane was still being read")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("publication did not drain")
	}
	<-finished
	if response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal(response.Code)
	}
	server.Publish(func(string) *StatusSnapshot { return &StatusSnapshot{Version: "replacement"} })
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":"replacement"`) {
		t.Fatalf("replacement was not published: %d %s", response.Code, response.Body)
	}
}
