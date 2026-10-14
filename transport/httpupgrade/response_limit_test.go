package httpupgrade

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol"
)

func TestUpgradeResponseHeadLimitAndTunnel(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(map[bool]string{true: "oversized head", false: "large tunnel"}[oversized], func(t *testing.T) {
			payload := strings.Repeat("x", 2<<20)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
				head := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
				if oversized {
					_, _ = io.WriteString(conn, head+"X-Flood: "+payload+"\r\n\r\n")
				} else {
					_, _ = io.WriteString(conn, head+"\r\n"+payload)
				}
			}))
			defer server.Close()
			dialer, err := NewDialer(&parentDialer{}, Config{Address: server.Listener.Addr().String()})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", "target.test:443")
			if oversized {
				if conn != nil {
					conn.Close()
				}
				if !errors.Is(err, protocol.ErrHTTPResponseHeaderTooLarge) {
					t.Fatalf("oversized upgrade head accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			got, err := io.ReadAll(conn)
			if err != nil || string(got) != payload {
				t.Fatalf("tunnel truncated to %d bytes: %v", len(got), err)
			}
		})
	}
}
