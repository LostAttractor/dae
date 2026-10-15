package ws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/gorilla/websocket"
)

func TestWebSocketResponseHeadLimitAndTunnel(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(map[bool]string{true: "oversized head", false: "large tunnel"}[oversized], func(t *testing.T) {
			payload := strings.Repeat("x", 2<<20)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header := make(http.Header)
				if oversized {
					header.Set("X-Flood", payload)
				}
				peer, err := (&websocket.Upgrader{HandshakeTimeout: 3 * time.Second}).Upgrade(w, r, header)
				if err != nil {
					return
				}
				defer peer.Close()
				_ = peer.SetWriteDeadline(time.Now().Add(3 * time.Second))
				_ = peer.WriteMessage(websocket.BinaryMessage, []byte(payload))
			}))
			defer server.Close()
			dialer := &Ws{ParentDialer: wsTestDialer{}, wsAddr: "ws" + strings.TrimPrefix(server.URL, "http")}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", "target.test:443")
			if oversized {
				if conn != nil {
					conn.Close()
				}
				if !errors.Is(err, protocol.ErrHTTPResponseHeaderTooLarge) {
					t.Fatalf("oversized WebSocket head accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			got := make([]byte, len(payload))
			if n, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
				t.Fatalf("WebSocket payload truncated to %d bytes: %v", n, err)
			}
		})
	}
}
