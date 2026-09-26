// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Controlled peer: its first stream is rejected before application processing.
// Subsequent streams return 200. Reads complete uploads before sending RST or GOAWAY.
func retryTestPeer(t *testing.T, cfg *tls.Config, fault, payload string) (string, *atomic.Int32) {
	t.Helper()
	cfg.NextProtos = []string{"h2"}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	var mu sync.Mutex
	var peers []net.Conn
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			peers = append(peers, conn)
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					return
				}
				if string(preface) != http2.ClientPreface {
					t.Error("non-h2 preface")
					return
				}
				framer := http2.NewFramer(conn, conn)
				if err := framer.WriteSettings(); err != nil {
					return
				}
				var uploaded bytes.Buffer
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						return
					}
					id := uint32(0)
					switch f := frame.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							_ = framer.WriteSettingsAck()
						}
					case *http2.HeadersFrame:
						if f.StreamEnded() {
							id = f.StreamID
						}
					case *http2.DataFrame:
						uploaded.Write(f.Data())
						if f.StreamEnded() {
							id = f.StreamID
						}
					}
					if id == 0 {
						continue
					}
					if uploaded.String() != payload {
						t.Errorf("upstream received %q, want %q", uploaded.String(), payload)
					}
					uploaded.Reset()
					if attempts.Add(1) == 1 {
						switch fault {
						case "REFUSED_STREAM":
							_ = framer.WriteRSTStream(id, http2.ErrCodeRefusedStream)
						case "GOAWAY":
							_ = framer.WriteGoAway(0, http2.ErrCodeNo, nil)
							return
						case "INTERNAL_ERROR":
							_ = framer.WriteRSTStream(id, http2.ErrCodeInternal)
						}
						continue
					}
					var block bytes.Buffer
					encoder := hpack.NewEncoder(&block)
					_ = encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: "2"})
					_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true})
					_ = framer.WriteData(id, true, []byte("ok"))
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for _, c := range peers {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.Addr().String(), &attempts
}

func TestHTTP2RequestRetry(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		for _, fault := range []string{"REFUSED_STREAM", "GOAWAY", "INTERNAL_ERROR"} {
			for _, mode := range []string{"direct", "passthrough", "snapshot", "rewrite"} {
				t.Run(method+"/"+fault+"/"+mode, func(t *testing.T) {
					authority, roots := http3TestAuthority(t)
					payload := ""
					if method == "POST" {
						payload = "grpc-request"
					}
					peer, attempts := retryTestPeer(t, authority.TLSConfig("example.com"), fault, payload)
					tlsConfig := &tls.Config{RootCAs: roots}
					var seenError string
					dialTarget := peer
					var proxy *httptest.Server
					if mode != "direct" {
						p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
							return func(e *plugin.Exchange) (*http.Response, error) {
								if method == "POST" && (mode == "snapshot" || mode == "rewrite") {
									view, err := plugin.SnapshotBody(&e.Request.Body, 1<<16, bodyMemory)
									if err != nil {
										return nil, err
									}
									defer view.Close()
									if mode == "rewrite" {
										plugin.SetRequestBody(e.Request, view)
									}
								}
								resp, err := next(e)
								if err != nil {
									seenError = err.Error()
								}
								return resp, err
							}
						}}
						host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: tlsConfig}, Instance{Plugin: p})
						handler, closeTransport := host.Handler("https", "example.com", 443, testUpstream(func(ctx context.Context, network, address string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, network, peer)
						}))
						defer closeTransport()
						proxy = httptest.NewUnstartedServer(handler)
						proxy.EnableHTTP2 = true
						proxy.TLS = authority.TLSConfig("example.com")
						proxy.StartTLS()
						defer proxy.Close()
						dialTarget = proxy.Listener.Addr().String()
					}
					transport := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, dialTarget)
					}}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
					var body io.Reader
					if method == "POST" {
						body = strings.NewReader(payload)
					}
					request, _ := http.NewRequest(method, "https://example.com/rpc", body)
					request.Header.Set("Content-Type", "application/grpc")
					response, err := client.Do(request)
					status := 0
					if response != nil {
						status = response.StatusCode
						_, _ = io.Copy(io.Discard, response.Body)
						response.Body.Close()
					}
					// Join the downstream server before inspecting the observer's fields.
					if proxy != nil {
						proxy.Close()
					}
					t.Logf("status=%d attempts=%d client_error=%v upstream_error=%s", status, attempts.Load(), err, seenError)
					if fault == "INTERNAL_ERROR" {
						if attempts.Load() != 1 {
							t.Fatal("retried an ambiguous error")
						}
						if mode == "direct" {
							if err == nil {
								t.Fatal("expected transport error")
							}
						} else if status != 502 || err != nil {
							t.Fatal("expected synthesized HTTP 502")
						}
						return
					}
					if err != nil || status != 200 || attempts.Load() != 2 {
						t.Fatalf("safe retry did not succeed: %s", seenError)
					}
				})
			}
		}
	}
}
