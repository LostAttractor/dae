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

func tcpDrainClient(t *testing.T, h *Host, roots *x509.CertPool, protocol string) (*http.Client, <-chan error) {
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
			err = h.ServeConn(conn, "example.com", port, testUpstream(func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unexpected upstream")
			}))
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
					client, served = tcpDrainClient(t, host, roots, protocol)
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
					if complete && err != nil {
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
