package http

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

func TestHTTP1ResponseHeadLimitAndTunnel(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(map[bool]string{true: "oversized head", false: "large tunnel"}[oversized], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			payload := strings.Repeat("x", 2<<20)
			peerDone := make(chan struct{})
			go func() {
				defer close(peerDone)
				defer server.Close()
				if _, err := stdhttp.ReadRequest(bufio.NewReader(server)); err != nil {
					return
				}
				response := "HTTP/1.1 200 OK\r\n\r\n" + payload
				if oversized {
					response = "HTTP/1.1 200 OK\r\nX-Flood: " + payload + "\r\n\r\n"
				}
				_, _ = io.WriteString(server, response)
				if oversized {
					// Keep a valid tunnel alive until the client closes it, so
					// peer closure cannot disguise acceptance of the huge head.
					_, _ = io.Copy(io.Discard, server)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := (&HttpProxy{}).connectHTTP1(ctx, client, "target.test:443")
			if oversized {
				if conn != nil || !errors.Is(err, protocol.ErrHTTPResponseHeaderTooLarge) {
					t.Fatalf("oversized CONNECT head accepted: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				got, err := io.ReadAll(conn)
				if err != nil || string(got) != payload {
					t.Fatalf("tunnel truncated to %d bytes: %v", len(got), err)
				}
			}
			<-peerDone
		})
	}
}
