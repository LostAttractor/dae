// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"github.com/daeuniverse/quic-go/quicvarint"
	"github.com/quic-go/qpack"
)

// Use a wire peer to reset before response headers. HTTPStreamer would flush
// response headers before handing the stream to the test, making it too late
// for the transport to retry H3_REQUEST_REJECTED.
func retryTestHTTP3Peer(t *testing.T, cfg *tls.Config, code http3.ErrCode) (net.Addr, *atomic.Int32) {
	t.Helper()
	cfg.NextProtos = []string{http3.NextProtoH3}
	listener, err := quic.Listen(http3TestPacketConn(t), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	var mu sync.Mutex
	var connections []*quic.Conn
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			workers.Go(func() {
				settings, err := conn.OpenUniStream()
				if err != nil {
					return
				}
				// Control stream (0), SETTINGS (4), empty payload (0).
				if _, err := settings.Write([]byte{0, 4, 0}); err != nil {
					return
				}
				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
					wire, err := io.ReadAll(io.LimitReader(stream, 4096))
					if err != nil {
						return
					}
					reader := bytes.NewReader(wire)
					var upload bytes.Buffer
					for reader.Len() > 0 {
						frame, err := quicvarint.Read(reader)
						if err != nil {
							t.Error(err)
							return
						}
						length, err := quicvarint.Read(reader)
						if err != nil || length > uint64(reader.Len()) {
							t.Errorf("invalid HTTP/3 frame length %d: %v", length, err)
							return
						}
						var sink io.Writer = io.Discard
						if frame == 0 { // DATA
							sink = &upload
						}
						_, _ = io.CopyN(sink, reader, int64(length))
					}
					if upload.String() != "grpc-request" {
						t.Errorf("upstream received %q", upload.String())
					}
					if attempts.Add(1) == 1 {
						stream.CancelWrite(quic.StreamErrorCode(code))
						continue
					}
					var headers bytes.Buffer
					_ = qpack.NewEncoder(&headers).WriteField(qpack.HeaderField{Name: ":status", Value: "204"})
					frame := quicvarint.Append(nil, 1) // HEADERS
					frame = quicvarint.Append(frame, uint64(headers.Len()))
					_, _ = stream.Write(append(frame, headers.Bytes()...))
					_ = stream.Close()
				}
			})
		}
	})
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, conn := range connections {
			_ = conn.CloseWithError(0, "test cleanup")
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.Addr(), &attempts
}

func TestHTTP3RequestRetry(t *testing.T) {
	for _, code := range []http3.ErrCode{http3.ErrCodeRequestRejected, http3.ErrCodeInternalError} {
		for _, mode := range []string{"passthrough", "snapshot", "rewrite"} {
			name := code.String() + "/" + mode
			t.Run(name, func(t *testing.T) {
				authority, roots := http3TestAuthority(t)
				peer, attempts := retryTestHTTP3Peer(t, authority.TLSConfig("example.com"), code)
				p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
					return func(e *plugin.Exchange) (*http.Response, error) {
						if mode != "passthrough" {
							view, err := plugin.SnapshotBody(&e.Request.Body, 64, bodyMemory)
							if err != nil {
								return nil, err
							}
							if mode == "rewrite" {
								plugin.SetRequestBody(e.Request, view)
							}
							view.Close()
						}
						return next(e)
					}
				}}
				host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, Instance{Plugin: p})
				client, _, _ := http3TestClient(t, host, roots, "example.com", peer)
				resp, err := client.Post("https://example.com/rpc", "application/grpc", strings.NewReader("grpc-request"))
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				wantStatus, wantAttempts := 204, int32(2)
				if code == http3.ErrCodeInternalError {
					wantStatus, wantAttempts = 502, 1
				}
				if resp.StatusCode != wantStatus || attempts.Load() != wantAttempts {
					t.Fatalf("status=%d attempts=%d, want %d/%d", resp.StatusCode, attempts.Load(), wantStatus, wantAttempts)
				}
			})
		}
	}
}
