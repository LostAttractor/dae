// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

// Compare one upstream with and without a pure-inspection MITM listener.
func passthroughClients(t *testing.T, downstream, upstream string, handler http.Handler) (direct, intercepted *http.Client) {
	t.Helper()
	ca, roots := http3TestAuthority(t)
	p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com"), PreserveRoute: true}}},
		wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler { return next }}
	h := testHost(t, Options{Authority: ca, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, Instance{Plugin: p})
	if upstream == "h3" {
		peer := http3TestUpstream(t, ca.TLSConfig("example.com"), handler)
		transport := h.http3Transport(func(context.Context, string) (net.PacketConn, net.Addr, error) {
			conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			return conn, peer, err
		})
		t.Cleanup(func() { _ = transport.Close() })
		intercepted, _, _ = http3TestClient(t, h, roots, "example.com", peer)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}, intercepted
	}
	backend := httptest.NewUnstartedServer(handler)
	backend.EnableHTTP2 = upstream == "h2"
	backend.TLS = ca.TLSConfig("example.com")
	if upstream == "h2" {
		backend.TLS.NextProtos = []string{"h2", "http/1.1"}
	}
	backend.StartTLS()
	t.Cleanup(backend.Close)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}
	transport := h.httpTransport(dial)
	t.Cleanup(transport.CloseIdleConnections)
	intercepted, _ = tcpDrainClient(t, h, roots, downstream, testUpstream(dial))
	if downstream == "h1" {
		intercepted.Transport.(*http.Transport).ForceAttemptHTTP2 = false
	}
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}, intercepted
}

func TestPassthroughRequestTrailers(t *testing.T) {
	for _, protocols := range []struct{ downstream, upstream string }{{"h1", "h1"}, {"h2", "h2"}, {"h2", "h1"}, {"h3", "h3"}} {
		for _, declared := range []bool{true, false} {
			for _, payload := range []string{"upload", ""} {
				t.Run(fmt.Sprintf("%s_%s/declared=%t/bytes=%d", protocols.downstream, protocols.upstream, declared, len(payload)), func(t *testing.T) {
					direct, intercepted := passthroughClients(t, protocols.downstream, protocols.upstream, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						if err != nil || string(body) != payload {
							t.Errorf("upstream body = %q, %v", body, err)
						}
						fmt.Fprint(w, r.Trailer.Get("X-Upload-Checksum"))
					}))
					for _, route := range []struct {
						name, protocol string
						client         *http.Client
					}{{"direct", protocols.upstream, direct}, {"mitm", protocols.downstream, intercepted}} {
						r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/upload", nil)
						if err != nil {
							t.Fatal(err)
						}
						r.Trailer = make(http.Header)
						if declared {
							r.Trailer["X-Upload-Checksum"] = nil
						}
						r.Body = &eofCallbackBody{Reader: strings.NewReader(payload), eof: func() { r.Trailer.Set("X-Upload-Checksum", "verified") }}
						r.ContentLength = int64(len(payload))
						if route.protocol == "h1" {
							r.ContentLength = -1 // HTTP/1 request trailers need chunked framing.
						}
						resp, err := route.client.Do(r)
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(resp.Body)
						resp.Body.Close()
						want := "verified"
						if !declared && route.protocol == "h2" {
							// Go's HTTP/2 server only delivers predeclared trailer keys.
							want = ""
						}
						if err != nil || resp.StatusCode != 200 || string(body) != want {
							t.Errorf("%s: status=%d trailer=%q, want %q; read=%v", route.name, resp.StatusCode, body, want, err)
						}
					}
				})
			}
		}
	}
}

// Populate trailers only when the transport actually finishes reading the body.
type eofCallbackBody struct {
	io.Reader
	eof func()
}

func (b *eofCallbackBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.eof != nil {
		b.eof()
		b.eof = nil
	}
	return n, err
}

func (*eofCallbackBody) Close() error { return nil }

func TestPassthroughEmptyRequestWithoutTrailers(t *testing.T) {
	for _, downstream := range []string{"h1", "h2"} {
		t.Run(downstream+"_h1", func(t *testing.T) {
			direct, intercepted := passthroughClients(t, downstream, "h1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Model an HTTP/1 API that requires an explicit upload length.
				if r.ContentLength != 0 || r.Header.Get("Content-Length") != "0" || len(r.TransferEncoding) != 0 {
					w.WriteHeader(http.StatusLengthRequired)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			for _, route := range []struct {
				name   string
				client *http.Client
			}{{"direct", direct}, {"mitm", intercepted}} {
				for _, method := range []string{http.MethodPost, http.MethodPut} {
					r, err := http.NewRequestWithContext(t.Context(), method, "https://example.com/empty", nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := route.client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					_, err = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if err != nil || resp.StatusCode != http.StatusOK {
						t.Errorf("%s %s: status=%d, read=%v", route.name, method, resp.StatusCode, err)
					}
				}
			}
		})
	}
}

func TestPassthroughContentType(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			direct, intercepted := passthroughClients(t, protocol, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header()["Content-Type"] = nil
				if r.URL.Path == "/typed" {
					w.Header().Set("Content-Type", "application/octet-stream")
				}
				w.Header().Set("Content-Length", "13")
				io.WriteString(w, "<html></html>")
			}))
			for _, route := range []struct {
				name   string
				client *http.Client
			}{{"direct", direct}, {"mitm", intercepted}} {
				for _, path := range []string{"/untyped", "/typed", "/untyped"} {
					resp, err := route.client.Get("https://example.com" + path)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					want := ""
					if path == "/typed" {
						want = "application/octet-stream"
					}
					if err != nil || string(body) != "<html></html>" || resp.Header.Get("Content-Type") != want {
						t.Errorf("%s%s: Content-Type=%q body=%q read=%v", route.name, path, resp.Header.Get("Content-Type"), body, err)
					}
				}
			}
		})
	}
}

func TestPassthroughFullDuplex(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			finished := make(chan error, 4)
			direct, intercepted := passthroughClients(t, protocol, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor == 1 {
					_ = http.NewResponseController(w).EnableFullDuplex()
				}
				var one [1]byte
				if _, err := io.ReadFull(r.Body, one[:]); err != nil {
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(one[:])
				_ = http.NewResponseController(w).Flush()
				_, err := io.Copy(w, r.Body)
				finished <- err
			}))
			for _, route := range []struct {
				name   string
				client *http.Client
			}{{"direct", direct}, {"mitm", intercepted}} {
				for _, complete := range []bool{true, false} {
					t.Run(fmt.Sprintf("%s/complete=%t", route.name, complete), func(t *testing.T) {
						ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
						defer cancel()
						reader, writer := io.Pipe()
						defer reader.Close()
						defer writer.Close()
						stop := context.AfterFunc(ctx, func() { writer.CloseWithError(ctx.Err()) })
						defer stop()
						first := make(chan error, 1)
						go func() { _, err := writer.Write([]byte("p")); first <- err }()
						r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/duplex", reader)
						if err != nil {
							t.Fatal(err)
						}
						resp, err := route.client.Do(r)
						if err != nil {
							t.Fatal(err)
						}
						defer resp.Body.Close()
						var one [1]byte
						if _, err := io.ReadFull(resp.Body, one[:]); err != nil || one[0] != 'p' {
							t.Fatalf("early response = %q, %v", one, err)
						}
						if err := <-first; err != nil {
							t.Fatal(err)
						}
						if !complete {
							cancel()
							reader.Close()
							writer.Close()
							resp.Body.Close()
							select {
							case <-finished:
							case <-time.After(2 * time.Second):
								t.Fatal("canceled upload left upstream handler blocked")
							}
							return
						}
						if _, err := io.WriteString(writer, "tail"); err != nil {
							t.Fatal(err)
						}
						writer.Close()
						body, err := io.ReadAll(resp.Body)
						if err != nil || string(body) != "tail" {
							t.Fatalf("remaining response = %q, %v", body, err)
						}
						if err := <-finished; err != nil {
							t.Fatalf("completed upload: %v", err)
						}
					})
				}
			}
		})
	}
}

func TestPassthroughHTTP3RetryTrailers(t *testing.T) {
	var attempts atomic.Int32
	_, client := passthroughClients(t, "h3", "h3", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "upload" || r.Trailer.Get("X-Upload-Checksum") != "verified" {
			t.Errorf("upstream attempt: body=%q trailer=%v read=%v", body, r.Trailer, err)
		}
		if attempts.Add(1) == 1 {
			// Reject before application processing, after receiving the full
			// upload. The MITM upstream transport must replay bytes and trailers.
			w.(http3.HTTPStreamer).HTTPStream().CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
			return
		}
		io.WriteString(w, "accepted")
	}))
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/upload", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Trailer = http.Header{"X-Upload-Checksum": nil}
	r.Body = &eofCallbackBody{Reader: strings.NewReader("upload"), eof: func() { r.Trailer.Set("X-Upload-Checksum", "verified") }}
	r.ContentLength = -1
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "accepted" || attempts.Load() != 2 {
		t.Fatalf("retry: status=%d body=%q attempts=%d read=%v", resp.StatusCode, body, attempts.Load(), err)
	}
}
