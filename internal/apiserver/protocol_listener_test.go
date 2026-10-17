package apiserver

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func waitClassifierCount(t *testing.T, listener *protocolListener, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		listener.mu.Lock()
		got := len(listener.pending)
		listener.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending classifications=%d want=%d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProtocolListenerIsolatesIdleSources(t *testing.T) {
	server, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	listener := server.listener.(*protocolListener)
	attacker := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	for range 16 {
		conn, err := attacker.DialContext(t.Context(), "tcp", server.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	waitClassifierCount(t, listener, 16)
	extra, err := attacker.DialContext(t.Context(), "tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("excess source connection was not closed: %v", err)
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("http://" + server.Addr().String() + "/api/status")
	if err != nil {
		t.Fatalf("other device denied service: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.Status)
	}
	for _, conn := range connections {
		conn.Close()
	}
	waitClassifierCount(t, listener, 0)
	transport.DialContext = attacker.DialContext
	transport.CloseIdleConnections()
	response, err = client.Get("http://" + server.Addr().String() + "/api/status")
	if err != nil {
		t.Fatalf("source quota not reclaimed: %v", err)
	}
	response.Body.Close()
	server.Close()
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if len(listener.pending) != 0 || len(listener.sources) != 0 {
		t.Fatal("closed listener retained accounting")
	}
}

func TestProtocolListenerKeepsGlobalLimit(t *testing.T) {
	server, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	for i := range maxPendingClassifications {
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(2+i/maxPendingClassificationsPerSource))}, Timeout: time.Second}
		conn, err := dialer.DialContext(t.Context(), "tcp", server.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	listener := server.listener.(*protocolListener)
	waitClassifierCount(t, listener, maxPendingClassifications)
	extra, err := net.DialTimeout("tcp", server.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("global bound failed: %v", err)
	}
	server.Close()
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if len(listener.pending) != 0 || len(listener.sources) != 0 {
		t.Fatal("shutdown did not reclaim idle slots")
	}
}
