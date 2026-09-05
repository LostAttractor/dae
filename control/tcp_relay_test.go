/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
)

func relayTestTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	peer := conn.(*net.TCPConn)
	t.Cleanup(func() { _ = peer.Close() })
	relay, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return relay, peer
}

type relayTestConn struct {
	read          func([]byte) (int, error)
	closeWriteErr error
	closed        chan struct{}
	writeClosed   chan struct{}
	closeOnce     sync.Once
	writeOnce     sync.Once
}

func relayTestNewConn() *relayTestConn {
	return &relayTestConn{
		closed:      make(chan struct{}),
		writeClosed: make(chan struct{}),
	}
}

func relayTestCleanupError() error {
	return netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Origin: netproxy.OriginLocalCleanup, Scope: netproxy.ScopeOperation})
}

func (c *relayTestConn) Read(p []byte) (int, error) {
	if c.read != nil {
		return c.read(p)
	}
	<-c.closed
	return 0, relayTestCleanupError()
}

func (c *relayTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *relayTestConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *relayTestConn) CloseWrite() error {
	c.writeOnce.Do(func() { close(c.writeClosed) })
	return c.closeWriteErr
}
func (c *relayTestConn) LocalAddr() net.Addr              { return nil }
func (c *relayTestConn) RemoteAddr() net.Addr             { return nil }
func (c *relayTestConn) SetDeadline(time.Time) error      { return nil }
func (c *relayTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *relayTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestRelayTCPSuppressesErrorCausedByAbort(t *testing.T) {
	for _, first := range []string{"upload", "download"} {
		t.Run(first, func(t *testing.T) {
			left, right := relayTestNewConn(), relayTestNewConn()
			source, destination := left, right
			if first == "download" {
				source, destination = right, left
			}
			wantErr := errors.New("transfer failed")
			reverseStarted := make(chan struct{})
			source.read = func([]byte) (int, error) {
				select {
				case <-reverseStarted:
					return 0, wantErr
				case <-source.closed:
					return 0, relayTestCleanupError()
				}
			}
			destination.read = func([]byte) (int, error) {
				close(reverseStarted)
				<-destination.closed
				return 0, relayTestCleanupError()
			}

			err := waitTCPRelayTest(t, startTCPRelayTest(t, left, right, time.Second))
			if !errors.Is(err, wantErr) {
				t.Fatalf("RelayTCP error = %v, want original error %v", err, wantErr)
			}
			if errors.Is(err, net.ErrClosed) {
				t.Fatalf("RelayTCP exposed a secondary error caused by abort: %v", err)
			}
		})
	}
}

type relayTestLeasedConn struct {
	net.Conn
	lease *netproxy.Lease
}

func (c *relayTestLeasedConn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *relayTestLeasedConn) CloseWrite() error {
	return c.Conn.(netproxy.CloseWriter).CloseWrite()
}

type relayTestSessionDialer struct {
	session *netproxy.SingleSession[struct{}]
	conns   []net.Conn
}

func (d *relayTestSessionDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	handle, err := d.session.CurrentHandle()
	if err != nil {
		return nil, err
	}
	conn := d.conns[0]
	d.conns = d.conns[1:]
	return &relayTestLeasedConn{Conn: conn, lease: handle.NewStreamLease()}, nil
}
func (*relayTestSessionDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func relayTestRuntime(t *testing.T, conns ...net.Conn) (*netproxy.Runtime, *netproxy.SingleSessionHandle[struct{}]) {
	t.Helper()
	session := netproxy.NewSingleSession(netproxy.SingleSessionConfig[struct{}]{
		Establish: func(context.Context) (struct{}, error) { return struct{}{}, nil },
	})
	runtime := netproxy.NewRuntime(netproxy.Layer{
		Data:      &relayTestSessionDialer{session: session, conns: conns},
		Sessions:  []netproxy.Session{session},
		Resources: []io.Closer{session},
	})
	t.Cleanup(func() {
		runtime.Retire()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := runtime.Wait(ctx); err != nil {
			t.Errorf("Runtime.Wait: %v", err)
		}
	})
	controller, _ := runtime.Session()
	if err := controller.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle, err := session.CurrentHandle()
	if err != nil {
		t.Fatal(err)
	}
	return runtime, handle
}

func relayTestStartRuntime(t *testing.T, runtime *netproxy.Runtime) (*net.TCPConn, <-chan error) {
	t.Helper()
	left, client := relayTestTCPPair(t)
	// Use the production lConn wrapper, with no unread client data: unread
	// TCP data can make an ordinary Close send RST without SetLinger(0).
	sniffer := sniffing.NewConnSniffer(left, 0)
	_, _ = sniffer.SniffTcp()
	right, err := runtime.Dialer().DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	return client, startTCPRelayTest(t, sniffer, right, time.Second)
}

func TestRelayTCPSessionAbortResetsDependentClients(t *testing.T) {
	// Reads deliberately stay blocked until the relay closes the connection:
	// Session abort must reach the client without waiting for a data-plane error.
	rights := []*relayTestConn{relayTestNewConn(), relayTestNewConn()}
	started := make(chan struct{}, len(rights))
	for _, right := range rights {
		right.read = func([]byte) (int, error) {
			started <- struct{}{}
			<-right.closed
			return 0, relayTestCleanupError()
		}
	}
	runtime, handle := relayTestRuntime(t, rights[0], rights[1])
	clients := make([]*net.TCPConn, len(rights))
	done := make([]<-chan error, len(rights))
	for i := range rights {
		clients[i], done[i] = relayTestStartRuntime(t, runtime)
	}
	for range rights {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("upstream Read did not start")
		}
	}

	// A separate Session must continue carrying traffic after this one fails.
	healthyRight, healthyServer := relayTestTCPPair(t)
	healthyRuntime, _ := relayTestRuntime(t, healthyRight)
	healthyClient, healthyDone := relayTestStartRuntime(t, healthyRuntime)
	cause := errors.New("owner detected an unusable transport")
	if !handle.Invalidate(cause) {
		t.Fatal("owner rejected current resource failure")
	}
	for i, client := range clients {
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("client %d read = %v, want ECONNRESET", i, err)
		}
		if err := waitTCPRelayTest(t, done[i]); !errors.Is(err, cause) {
			t.Fatalf("relay %d error = %v, lost owner cause %v", i, err, cause)
		}
	}
	if _, err := healthyServer.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err := io.ReadFull(healthyClient, response[:]); err != nil || string(response[:]) != "ok" {
		t.Fatalf("unrelated Session response = %q, %v", response, err)
	}
	_ = healthyClient.CloseWrite()
	_ = healthyServer.CloseWrite()
	if err := waitTCPRelayTest(t, healthyDone); err != nil {
		t.Fatal(err)
	}
}

func TestRelayTCPOwnerAbortPrecedesDerivedEOF(t *testing.T) {
	right := relayTestNewConn()
	runtime, handle := relayTestRuntime(t, right)
	cause := errors.New("owner closed failed carrier")
	right.read = func([]byte) (int, error) {
		handle.Lease().Abort(cause)
		return 0, io.EOF
	}
	client, done := relayTestStartRuntime(t, runtime)
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("client read = %v, want ECONNRESET instead of a derived FIN", err)
	}
	if err := waitTCPRelayTest(t, done); !errors.Is(err, cause) {
		t.Fatalf("relay error = %v, lost owner cause %v", err, cause)
	}
}

func TestRelayTCPReturnedFatalErrorDoesNotAuthorizeReset(t *testing.T) {
	right := relayTestNewConn()
	fatal := &quic.TransportError{Remote: true, ErrorCode: quic.InternalError}
	right.read = func([]byte) (int, error) { return 0, fatal }
	runtime, _ := relayTestRuntime(t, right)
	client, done := relayTestStartRuntime(t, runtime)
	if err := waitTCPRelayTest(t, done); !errors.Is(err, fatal) {
		t.Fatalf("relay error = %v, want %v", err, fatal)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client read = %v, want ordinary close without owner abort", err)
	}
}

func TestRelayTCPGracefulLifecycleKeepsActiveConnection(t *testing.T) {
	for _, action := range []string{"invalidate", "local cleanup", "retire"} {
		t.Run(action, func(t *testing.T) {
			right, server := relayTestTCPPair(t)
			runtime, handle := relayTestRuntime(t, right)
			client, done := relayTestStartRuntime(t, runtime)
			switch action {
			case "invalidate":
				handle.Lease().Invalidate(errors.New("stop allocating on draining transport"))
			case "local cleanup":
				handle.Invalidate(relayTestCleanupError())
			case "retire":
				runtime.Retire()
			}
			if _, err := server.Write([]byte("response")); err != nil {
				t.Fatal(err)
			}
			_ = server.CloseWrite()
			got, err := io.ReadAll(client)
			if err != nil || string(got) != "response" {
				t.Fatalf("response = %q, %v; lifecycle action interrupted active relay", got, err)
			}
			_ = client.CloseWrite()
			if err := waitTCPRelayTest(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
