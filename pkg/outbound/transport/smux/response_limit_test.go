package smux

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestRejectionMessageBound(t *testing.T) {
	for _, size := range []int{0, 32, 1024, 2 << 20} {
		client, server := net.Pipe()
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		done := make(chan int, 1)
		go func() {
			defer server.Close()
			n, _ := io.WriteString(server, "\x01"+strings.Repeat("x", size))
			done <- n
		}()
		err := ReadResponse(client)
		_ = client.Close()
		written := <-done
		if err == nil || netproxy.ClassifyFailure(err).Reason != netproxy.ReasonRejected {
			t.Fatalf("rejection size %d: %v", size, err)
		}
		if written > 1026 || len(err.Error()) > 1200 {
			t.Fatalf("unbounded rejection: read=%d error=%d", written, len(err.Error()))
		}
		if strings.Contains(err.Error(), "(truncated)") != (size > 1024) {
			t.Fatalf("incorrect truncation marker for %d bytes: %v", size, err)
		}
	}
}

func TestSuccessfulResponseDoesNotConsumePayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	go func() {
		defer server.Close()
		_, _ = io.WriteString(server, "\x00payload")
	}()
	if err := ReadResponse(client); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(client)
	if err != nil || string(payload) != "payload" {
		t.Fatalf("payload: %q %v", payload, err)
	}
}
