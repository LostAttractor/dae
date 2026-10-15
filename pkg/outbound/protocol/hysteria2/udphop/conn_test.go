package udphop

import (
	"context"
	"errors"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testHopAddr() *UDPHopAddr {
	return &UDPHopAddr{
		IP:      net.IPv4(127, 0, 0, 1),
		Ports:   []uint16{443},
		PortStr: "443",
	}
}

func TestUDPHopPacketConnDoesNotExposeSyscallConn(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	conn, err := NewUDPHopPacketConn(context.Background(), testHopAddr(), time.Hour, func(context.Context, net.Addr) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, ok := conn.(syscall.Conn); ok {
		t.Fatal("UDP hop connection unexpectedly exposes SyscallConn")
	}
}

type controlledConn struct {
	net.Conn
	done            chan struct{}
	writeStarted    chan struct{}
	timeoutReturned chan struct{}
	remaining       int
	once            sync.Once
	writeOnce       sync.Once
	lease           *netproxy.Lease
}

func newControlledConn() *controlledConn {
	return &controlledConn{done: make(chan struct{}), writeStarted: make(chan struct{}), lease: netproxy.NewLease(netproxy.NewResourceRef())}
}
func (c *controlledConn) Read(p []byte) (int, error) {
	if c.remaining > 0 {
		c.remaining--
		p[0] = 1
		return 1, nil
	}
	if c.timeoutReturned != nil {
		close(c.timeoutReturned)
		c.timeoutReturned = nil
		return 0, os.ErrDeadlineExceeded
	}
	<-c.done
	return 0, net.ErrClosed
}
func (c *controlledConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.done
	return 0, net.ErrClosed
}
func (c *controlledConn) Close() error {
	c.once.Do(func() { c.lease.Invalidate(net.ErrClosed); close(c.done) })
	return nil
}
func (c *controlledConn) LocalAddr() net.Addr              { return netproxy.NewAddr("udp", "127.0.0.1:1") }
func (c *controlledConn) RemoteAddr() net.Addr             { return netproxy.NewAddr("udp", "127.0.0.1:443") }
func (c *controlledConn) SetDeadline(time.Time) error      { return nil }
func (c *controlledConn) SetReadDeadline(time.Time) error  { return nil }
func (c *controlledConn) SetWriteDeadline(time.Time) error { return nil }
func (c *controlledConn) DependencyLease() *netproxy.Lease { return c.lease }
func waitClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker failed to stop")
	}
}
func closePromptly(t *testing.T, c net.PacketConn) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = c.Close(); close(done) }()
	waitClosed(t, done)
}
func TestCloseUnblocksWriteAndJoinsReceivers(t *testing.T) {
	raw := newControlledConn()
	conn, err := NewUDPHopPacketConn(context.Background(), testHopAddr(), time.Hour, func(context.Context, net.Addr) (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() { _, _ = conn.WriteTo([]byte("blocked"), nil); close(done) }()
	waitClosed(t, raw.writeStarted)
	closePromptly(t, conn)
	waitClosed(t, done)
}
func TestCloseDrainsFullReceiveQueueAfterSocketTimeout(t *testing.T) {
	raw := newControlledConn()
	raw.remaining = packetQueueSize
	returned := make(chan struct{})
	raw.timeoutReturned = returned
	conn, err := NewUDPHopPacketConn(context.Background(), testHopAddr(), time.Hour, func(context.Context, net.Addr) (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	waitClosed(t, returned)
	closePromptly(t, conn)
	if n := len(conn.(*udpHopPacketConn).recvQueue); n != 0 {
		t.Fatalf("retained %d pooled packets after Close", n)
	}
}
func TestReadDeadlineResetPreservesReceiver(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	initial, cancel := context.WithCancel(context.Background())
	conn, err := NewUDPHopPacketConn(initial, testHopAddr(), time.Hour, func(context.Context, net.Addr) (net.Conn, error) { return local, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := conn.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline=%v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = peer.Write([]byte("x")) }()
	p := make([]byte, 1)
	if n, _, err := conn.ReadFrom(p); err != nil || n != 1 || p[0] != 'x' {
		t.Fatalf("reset ReadFrom=%d,%q,%v", n, p, err)
	}
}
func TestRotationKeepsStableLeaseAndCurrentFailureKeepsCause(t *testing.T) {
	conns := []*controlledConn{newControlledConn(), newControlledConn(), newControlledConn()}
	next := 0
	conn, err := NewUDPHopPacketConn(context.Background(), testHopAddr(), time.Hour, func(context.Context, net.Addr) (net.Conn, error) { c := conns[next]; next++; return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hopper := conn.(*udpHopPacketConn)
	lease := hopper.DependencyLease()
	hopper.hop()
	hopper.hop()
	waitClosed(t, conns[0].done)
	if !lease.Valid() || lease != hopper.DependencyLease() || lease.AbortCause() != nil {
		t.Fatal("retiring first hop invalidated stable hopper lease")
	}
	cause := netproxy.WrapFailure(syscall.ECONNRESET, netproxy.Failure{Resource: conns[2].lease.Resource(), Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerTCP, Reason: netproxy.ReasonReset, Origin: netproxy.OriginPeer})
	conns[2].lease.Abort(cause)
	waitClosed(t, lease.Done())
	closePromptly(t, hopper)
	failure := netproxy.ClassifyFailure(lease.Cause())
	if !errors.Is(lease.Cause(), syscall.ECONNRESET) || failure.Layer != netproxy.LayerTCP || failure.Resource != conns[2].lease.Resource() {
		t.Fatalf("lost parent cause: %+v", failure)
	}
	if !errors.Is(lease.AbortCause(), cause) {
		t.Fatalf("hopper lost current parent abort: %v", lease.AbortCause())
	}
	for _, c := range conns {
		waitClosed(t, c.done)
	}
}

type writeSignalConn struct {
	net.Conn
	entered chan struct{}
}

func (c *writeSignalConn) Write(p []byte) (int, error) { close(c.entered); return c.Conn.Write(p) }
func TestWriteDeadlineReachesWriterOnPreviousHop(t *testing.T) {
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	started := make(chan struct{})
	count := 0
	conn, err := NewUDPHopPacketConn(context.Background(), testHopAddr(), time.Hour, func(context.Context, net.Addr) (net.Conn, error) {
		count++
		if count == 1 {
			return &writeSignalConn{first, started}, nil
		}
		return second, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	result := make(chan error, 1)
	go func() { _, err := conn.WriteTo([]byte("blocked"), nil); result <- err }()
	waitClosed(t, started)
	conn.(*udpHopPacketConn).hop()
	_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("pending Write=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline missed pending writer on previous hop")
	}
}

func TestCloseCancelsAndJoinsHopDial(t *testing.T) {
	raw := newControlledConn()
	started, returned := make(chan struct{}), make(chan struct{})
	count := 0
	conn, err := NewUDPHopPacketConn(context.Background(), testHopAddr(), 5*time.Second, func(ctx context.Context, _ net.Addr) (net.Conn, error) {
		count++
		if count == 1 {
			return raw, nil
		}
		close(started)
		<-ctx.Done()
		close(returned)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-started:
	case <-time.After(6 * time.Second):
		t.Fatal("hop dial did not start")
	}
	closePromptly(t, conn)
	select {
	case <-returned:
	default:
		t.Fatal("Close returned before hop dial exited")
	}
}
