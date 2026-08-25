package dialer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type runtimeResourceDialer struct {
	closes atomic.Int32
	peer   net.Conn
}

type concreteConn struct{ net.Conn }

type concreteConnDialer struct{ peer net.Conn }

type closeWriteConn struct {
	net.Conn
	closedWrite atomic.Bool
}

func (c *closeWriteConn) CloseWrite() error {
	c.closedWrite.Store(true)
	return nil
}

type closeWriteDialer struct {
	conn *closeWriteConn
	peer net.Conn
}

func (d *closeWriteDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	conn, peer := net.Pipe()
	d.conn = &closeWriteConn{Conn: conn}
	d.peer = peer
	return d.conn, nil
}
func (d *closeWriteDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *closeWriteDialer) Close() error { return nil }

func (d *concreteConnDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	conn, peer := net.Pipe()
	d.peer = peer
	return &concreteConn{Conn: conn}, nil
}
func (*concreteConnDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (d *runtimeResourceDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, peer := net.Pipe()
	d.peer = peer
	return client, nil
}
func (d *runtimeResourceDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *runtimeResourceDialer) Close() error {
	d.closes.Add(1)
	return nil
}

func TestTransportRuntimeDefersCloseForActiveConnection(t *testing.T) {
	resource := new(runtimeResourceDialer)
	runtime := newTransportRuntime(netproxy.NewRuntime(resource))
	conn, err := runtime.owned.Dialer().DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer resource.peer.Close()
	runtime.retire()
	if runtime.connected() {
		t.Fatal("closed runtime remained connected")
	}
	if got := resource.closes.Load(); got != 0 {
		t.Fatalf("resource closed with active connection: %d", got)
	}
	if _, err := runtime.owned.Dialer().DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after runtime retire error = %v, want net.ErrClosed", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.owned.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes after connection release = %d, want 1", got)
	}
}

func TestStatelessRuntimeUsesDataPlaneFacade(t *testing.T) {
	transport := new(concreteConnDialer)
	runtime := newTransportRuntime(netproxy.NewRuntime(transport))
	conn, err := runtime.owned.Dialer().DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer transport.peer.Close()
	if _, ok := conn.(*concreteConn); ok {
		t.Fatalf("stateless connection exposed concrete type %T", conn)
	}
	runtime.retire()
	if _, err := runtime.owned.Dialer().DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after runtime retire error = %v, want net.ErrClosed", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.owned.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTrackedConnectionPreservesCloseWrite(t *testing.T) {
	transport := new(closeWriteDialer)
	runtime := newTransportRuntime(netproxy.NewRuntime(transport))
	conn, err := runtime.owned.Dialer().DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer transport.peer.Close()
	closeWriter, ok := conn.(netproxy.CloseWriter)
	if !ok {
		t.Fatalf("tracked connection type %T lost CloseWrite", conn)
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !transport.conn.closedWrite.Load() {
		t.Fatal("CloseWrite was not delegated")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.retire()
	if err := runtime.owned.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNormalSessionCloseRemainsTerminal(t *testing.T) {
	transport := new(statefulTestDialer)
	runtime := newTransportRuntime(netproxy.NewRuntime(transport))
	transport.transition(netproxy.SessionClosed, nil)
	deadline := time.Now().Add(time.Second)
	for runtime.stateSnapshot().State != netproxy.SessionClosed && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(time.Millisecond)
	if state := runtime.stateSnapshot().State; state != netproxy.SessionClosed {
		t.Fatalf("state after closed stream = %s, want closed", state)
	}
	runtime.retire()
	if err := runtime.owned.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}
