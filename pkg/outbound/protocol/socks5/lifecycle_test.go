package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type testParent struct {
	conn    net.Conn
	listen  func(context.Context, string) (net.PacketConn, error)
	resolve func(context.Context, string) (*net.UDPAddr, error)
}

func (p testParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (p testParent) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return p.listen(ctx, address)
}

func (p testParent) ResolveUDPAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	if p.resolve != nil {
		return p.resolve(ctx, address)
	}
	return netproxy.ResolveUDPAddr(ctx, nil, address)
}

type wireStep struct{ read, write []byte }

func runPeer(conn net.Conn, steps []wireStep) error {
	for _, step := range steps {
		if len(step.read) > 0 {
			got := make([]byte, len(step.read))
			if _, err := io.ReadFull(conn, got); err != nil {
				return err
			}
			if !bytes.Equal(got, step.read) {
				return fmt.Errorf("wire %x, want %x", got, step.read)
			}
		}
		if len(step.write) > 0 {
			if _, err := conn.Write(step.write); err != nil {
				return err
			}
		}
	}
	return nil
}
func tcpRequest() []byte {
	return append(append([]byte{5, 1, 0, 3, 11}, []byte("example.org")...), 0, 80)
}

var successReply = []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}

func TestDialHandshakeWireAndCancellation(t *testing.T) {
	t.Run("authenticated TCP", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()
		steps := []wireStep{{[]byte{5, 2, 0, 2}, []byte{5, 2}}, {[]byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}, []byte{1, 0}}, {tcpRequest(), successReply}}
		done := make(chan error, 1)
		go func() { done <- runPeer(server, steps) }()
		d, _ := NewSocks5("socks5://user:pass@proxy:1080", testParent{conn: client})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", "example.org:80")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cancel blocked greeting", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()
		d, _ := NewSocks5("socks5://proxy:1080", testParent{conn: client})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", "example.org:80")
		if conn != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%v %v", conn, err)
		}
		if _, err := server.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("carrier remained open: %v", err)
		}
	})
}

func TestHandshakeRejectsInvalidRepliesAndCloses(t *testing.T) {
	for _, tc := range []struct {
		name, user string
		steps      []wireStep
	}{
		{"method version", "", []wireStep{{[]byte{5, 1, 0}, []byte{4, 0}}}},
		{"unknown method", "", []wireStep{{[]byte{5, 1, 0}, []byte{5, 1}}}},
		{"unoffered password", "", []wireStep{{[]byte{5, 1, 0}, []byte{5, 2}}}},
		{"auth version", "user:pass@", []wireStep{{[]byte{5, 2, 0, 2}, []byte{5, 2}}, {[]byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}, []byte{2, 0}}}},
		{"reply version", "", []wireStep{{[]byte{5, 1, 0}, []byte{5, 0}}, {tcpRequest(), []byte{4, 0, 0}}}},
		{"reply reserved", "", []wireStep{{[]byte{5, 1, 0}, []byte{5, 0}}, {tcpRequest(), []byte{5, 0, 1}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			done := make(chan error, 1)
			go func() { done <- runPeer(server, tc.steps) }()
			d, _ := NewSocks5("socks5://"+tc.user+"proxy:1080", testParent{conn: client})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, "tcp", "example.org:80")
			if conn != nil || err == nil {
				t.Fatalf("%v %v", conn, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := server.Read(make([]byte, 1)); err != io.EOF {
				t.Fatal("handshake failure leaked carrier")
			}
		})
	}
}

type failedWriteConn struct {
	net.Conn
	err    error
	closed bool
}

func (c *failedWriteConn) Write(b []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	return len(b) - 1, nil
}
func (c *failedWriteConn) Close() error { c.closed = true; return c.Conn.Close() }
func TestHandshakePreservesUnderlyingCauseAndShortWrite(t *testing.T) {
	cause := netproxy.WrapFailure(errors.New("carrier failure"), netproxy.Failure{Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerQUIC})
	for _, failure := range []error{cause, nil} {
		client, server := net.Pipe()
		conn := &failedWriteConn{Conn: client, err: failure}
		d, _ := NewSocks5("socks5://proxy:1080", testParent{conn: conn})
		_, err := d.DialContext(context.Background(), "tcp", "example.org:80")
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) || !conn.closed {
			t.Fatalf("lost cause or carrier: %v, closed=%v", err, conn.closed)
		}
		server.Close()
	}
}

func TestUDPRelaySetupFailureClosesControl(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	request := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	go func() {
		done <- runPeer(server, []wireStep{{[]byte{5, 1, 0}, []byte{5, 0}}, {request, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0x12, 0x34}}})
	}()
	cause := errors.New("cannot open UDP carrier")
	d, _ := NewSocks5("socks5://proxy.example:1080", testParent{conn: client, resolve: func(_ context.Context, addr string) (*net.UDPAddr, error) {
		if addr != "proxy.example:4660" {
			t.Errorf("unspecified relay address was not replaced: %s", addr)
		}
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4660}, nil
	}, listen: func(_ context.Context, addr string) (net.PacketConn, error) {
		if addr != "127.0.0.1:4660" {
			t.Errorf("relay address was not pinned: %s", addr)
		}
		return nil, cause
	}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := d.ListenPacket(ctx, "target.example:53")
	if conn != nil || !errors.Is(err, cause) {
		t.Fatalf("%v %v", conn, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("UDP setup failure leaked control connection")
	}
}

func TestUDPWireBoundsAndControlClosure(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	port := relay.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	peerDone := make(chan error, 1)
	go func() {
		peerDone <- runPeer(server, []wireStep{{[]byte{5, 1, 0}, []byte{5, 0}}, {[]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}, reply}})
	}()
	var local net.PacketConn
	d, _ := NewSocks5("socks5://127.0.0.1:1080", testParent{conn: client, listen: func(_ context.Context, addr string) (net.PacketConn, error) {
		if addr != "127.0.0.1:"+strconv.Itoa(port) {
			t.Errorf("relay %s", addr)
		}
		var err error
		local, err = net.ListenPacket("udp", "127.0.0.1:0")
		return local, err
	}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := d.ListenPacket(ctx, "target.example:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	pc := conn.(*PktConn)
	// Control bytes have no application meaning and must not close the association.
	if _, err := server.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	target := netproxy.NewAddr("udp", "example.org:53")
	if n, err := conn.WriteTo([]byte("query"), target); n != 5 || err != nil {
		t.Fatalf("write %d %v", n, err)
	}
	wire := make([]byte, 256)
	_ = relay.SetReadDeadline(time.Now().Add(time.Second))
	n, source, err := relay.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	expected := append(append([]byte{0, 0, 0, 3, 11}, []byte("example.org")...), 0, 53)
	expected = append(expected, []byte("query")...)
	if !bytes.Equal(wire[:n], expected) {
		t.Fatalf("wire=%x", wire[:n])
	}
	for _, bad := range [][]byte{{1, 0, 0, 1}, {0, 0, 1, 1}, {0, 0, 0, 3, 10, 'a'}} {
		_, _ = relay.WriteTo(bad, source)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if n, _, err := conn.ReadFrom(make([]byte, 2)); n != 0 || err == nil {
			t.Fatalf("accepted malformed datagram: %d %v", n, err)
		}
	}
	response := append(bytes.Clone(expected[:len(expected)-5]), []byte("long response")...)
	_, _ = relay.WriteTo(response, source)
	b := make([]byte, 2)
	n, addr, err := conn.ReadFrom(b)
	if n != 2 || string(b) != "lo" || addr.String() != "example.org:53" || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short response %d %q %v %v", n, b, addr, err)
	}
	if _, err := conn.WriteTo(make([]byte, 65507), target); err == nil {
		t.Fatal("oversized datagram accepted")
	}
	_ = conn.SetReadDeadline(time.Time{})
	blocked := make(chan error, 1)
	go func() { _, _, err := conn.ReadFrom(make([]byte, 16)); blocked <- err }()
	server.Close()
	select {
	case err := <-blocked:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("lost control EOF: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control EOF did not release UDP read")
	}
	if pc.lease.Valid() {
		t.Fatal("closed control left UDP lease valid")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pc.controlDone:
	default:
		t.Fatal("control observer outlived close")
	}
	select {
	case <-pc.leaseDone:
	default:
		t.Fatal("lease observer outlived close")
	}
}

type leasedControl struct {
	net.Conn
	lease *netproxy.Lease
}

func (c leasedControl) DependencyLease() *netproxy.Lease { return c.lease }
func TestUDPParentInvalidationClosesBothCarriers(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	parent := netproxy.NewLease(netproxy.NewResourceRef())
	pc := NewPktConn(packet, leasedControl{client, parent}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	cause := netproxy.WrapFailure(errors.New("parent died"), netproxy.Failure{Scope: netproxy.ScopeSharedResource, Resource: parent.Resource(), Layer: netproxy.LayerQUIC})
	parent.Invalidate(cause)
	select {
	case <-pc.controlDone:
	case <-time.After(time.Second):
		t.Fatal("parent invalidation did not close control reader")
	}
	if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, cause) {
		t.Fatalf("lost parent failure: %v", err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
}

type failedReadControl struct {
	net.Conn
	cause error
	first bool
}

func (c *failedReadControl) Read(b []byte) (int, error) {
	if !c.first {
		c.first = true
		return 0, c.cause
	}
	return c.Conn.Read(b)
}
func TestUDPControlTimeoutDoesNotHideCarrierFailure(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fatal := netproxy.WrapFailure(errors.New("QUIC carrier closed"), netproxy.Failure{Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerQUIC, Reason: netproxy.ReasonReset})
	ctrl := &failedReadControl{Conn: client, cause: errors.Join(context.DeadlineExceeded, fatal)}
	pc := NewPktConn(packet, ctrl, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	defer pc.Close()
	select {
	case <-pc.controlDone:
	case <-time.After(time.Second):
		t.Fatal("timeout hid shared carrier failure")
	}
	if !errors.Is(pc.lease.Cause(), fatal) {
		t.Fatalf("lost fatal cause: %v", pc.lease.Cause())
	}
}
