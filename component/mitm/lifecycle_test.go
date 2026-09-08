// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
)

func waitHostState(t *testing.T, h *Host, ready func(*Host) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		done := ready(h)
		h.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("host did not reach expected lifecycle state")
}

func tcpDrainClient(t *testing.T, h *Host, roots *x509.CertPool, protocol string, plan UpstreamPlanner) (*http.Client, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			port := uint16(443)
			if protocol == "http" {
				port = 80
			}
			err = h.ServeConn(conn, "example.com", port, plan)
		}
		served <- err
	}()
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}, served
}

func TestMITMDrain(t *testing.T) {
	for _, protocol := range []string{"http", "h2", "h3"} {
		for _, complete := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/complete=%t", protocol, complete), func(t *testing.T) {
				authority, roots := http3TestAuthority(t)
				started, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
				p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(plugin.Flow, plugin.Handler) plugin.Handler {
					return func(e *plugin.Exchange) (*http.Response, error) {
						close(started)
						select {
						case <-release:
							return response("completed during drain"), nil
						case <-e.Request.Context().Done():
							close(canceled)
							return nil, e.Request.Context().Err()
						}
					}
				}}
				host := testHost(t, Options{Authority: authority, DrainTimeout: 150 * time.Millisecond}, Instance{Plugin: p})
				scheme := "https"
				var client *http.Client
				var served <-chan error
				if protocol == "h3" {
					client, served, _ = http3TestClient(t, host, roots, "example.com", nil)
				} else {
					client, served = tcpDrainClient(t, host, roots, protocol, nil)
					if protocol == "http" {
						scheme = "http"
					}
				}
				requestDone := make(chan struct{})
				go func() {
					defer close(requestDone)
					resp, err := client.Get(scheme + "://example.com/")
					if err == nil {
						wantProto := map[string]int{"http": 1, "h2": 2, "h3": 3}[protocol]
						if resp.ProtoMajor != wantProto {
							t.Errorf("protocol = %s, want HTTP/%d", resp.Proto, wantProto)
						}
						body, _ := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						if complete && string(body) != "completed during drain" {
							t.Errorf("drain response: %q", body)
						}
					} else if complete {
						t.Error(err)
					}
				}()
				select {
				case <-started:
				case <-time.After(3 * time.Second):
					t.Fatal("request not started")
				}
				closed := make(chan error, 1)
				go func() { closed <- host.Close() }()
				waitHostState(t, host, func(h *Host) bool { return h.closed })
				if complete {
					close(release)
				}
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("host did not close")
				}
				if !complete {
					select {
					case <-canceled:
					case <-time.After(time.Second):
						t.Fatal("drain did not cancel active request")
					}
				}
				select {
				case <-served:
				case <-time.After(time.Second):
					t.Fatal("drain did not stop serving")
				}
				<-requestDone
			})
		}
	}
}

func TestMITMForceCloseStreamAndUpgrade(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgrade=%t", upgrade), func(t *testing.T) {
			upstreamClosed := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(upstreamClosed)
				if upgrade {
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
					_ = rw.Flush()
					_, _ = io.Copy(io.Discard, rw)
				} else {
					_, _ = io.WriteString(w, "unfinished stream")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}
			}))
			defer upstream.Close()
			host := testHost(t, Options{DrainTimeout: 20 * time.Millisecond})
			client, served := tcpDrainClient(t, host, nil, "http", testUpstream(func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
			}))
			req, err := http.NewRequest("GET", "http://example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if upgrade {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if upgrade && resp.StatusCode != http.StatusSwitchingProtocols || !upgrade && resp.StatusCode != http.StatusOK {
				t.Fatalf("unexpected response: %s", resp.Status)
			}
			closed := make(chan error, 1)
			go func() { closed <- host.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("stream or upgraded connection blocked forced cleanup")
			}
			select {
			case <-served:
			case <-time.After(time.Second):
				t.Fatal("downstream connection was not retired")
			}
			select {
			case <-upstreamClosed:
			case <-time.After(time.Second):
				t.Fatal("upstream connection was not retired")
			}
		})
	}
}

type drainCleanupPlugin struct {
	*testPlugin
	close func() error
}

func (p *drainCleanupPlugin) Close() error { return p.close() }

func TestMITMDrainWaitsForCleanup(t *testing.T) {
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cleanupErr := fmt.Errorf("plugin cleanup failed: %w", context.DeadlineExceeded)
	pluginClosed := make(chan struct{})
	p := &drainCleanupPlugin{testPlugin: &testPlugin{
		plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}},
		wrap: func(plugin.Flow, plugin.Handler) plugin.Handler {
			return func(e *plugin.Exchange) (*http.Response, error) {
				close(started)
				<-e.Request.Context().Done()
				close(canceled)
				<-release // Cleanup must finish before retiring plugin resources.
				return nil, e.Request.Context().Err()
			}
		},
	}, close: func() error { close(pluginClosed); return cleanupErr }}
	authority, _ := http3TestAuthority(t)
	host := testHost(t, Options{Authority: authority, DrainTimeout: 20 * time.Millisecond}, Instance{Plugin: p})
	handler, closePools := host.Handler("http", "example.com", 80, nil)
	defer closePools()
	go handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/", nil))
	<-started
	closed := make(chan error, 1)
	go func() { closed <- host.Close() }()
	<-canceled
	select {
	case err := <-closed:
		close(release)
		t.Fatalf("Close returned before forced cleanup finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closed:
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("Close lost the plugin cleanup error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after request cleanup")
	}
	select {
	case <-pluginClosed:
	default:
		t.Fatal("Close returned before closing the plugin")
	}
	if !errors.Is(host.Close(), cleanupErr) {
		t.Fatal("repeated Close lost the cleanup error")
	}
}

func TestMITMCloseBeforeHandshake(t *testing.T) {
	for _, protocol := range []string{"tcp", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			authority, _ := http3TestAuthority(t)
			host := testHost(t, Options{Authority: authority, DrainTimeout: time.Second})
			served := make(chan error, 1)
			if protocol == "tcp" {
				server, client := net.Pipe()
				defer client.Close()
				go func() { served <- host.ServeConn(server, "example.com", 443, nil) }()
			} else {
				server, client := http3TestPacketConn(t), http3TestPacketConn(t)
				flow := plugin.Flow{Host: "example.com", Port: 443,
					Source: netip.MustParseAddrPort(client.LocalAddr().String()), Destination: netip.MustParseAddrPort(server.LocalAddr().String())}
				go func() {
					served <- host.ServePacketConn(server, flow, testUpstream(nil), testPacketUpstream(func(context.Context, string) (net.PacketConn, net.Addr, error) {
						return nil, nil, errors.New("unexpected upstream")
					}))
				}()
			}
			waitHostState(t, host, func(h *Host) bool { return len(h.connections) == 1 })
			if err := host.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-served:
			case <-time.After(time.Second):
				t.Fatal("an unfinished handshake prevented shutdown")
			}
		})
	}
}
