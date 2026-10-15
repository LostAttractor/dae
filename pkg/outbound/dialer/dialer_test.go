package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	"github.com/daeuniverse/quic-go"
)

type runtimeTestDialer struct {
	state  *netproxy.StateBroadcaster
	closes atomic.Int32
}

func (d *runtimeTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (d *runtimeTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *runtimeTestDialer) Connect(context.Context) error { return nil }
func (d *runtimeTestDialer) Snapshot() netproxy.StateEvent { return d.state.Snapshot() }
func (d *runtimeTestDialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.state.WatchState(ctx)
}
func (d *runtimeTestDialer) Close() error {
	d.closes.Add(1)
	d.state.Transition(netproxy.SessionClosed, nil)
	return nil
}

type composingBuilder struct {
	sawParentSession bool
	sawParentCloser  bool
}

type failingBuilder struct {
	err error
}

func (b *composingBuilder) Build(_ *ExtraOption, upstream Upstream) (netproxy.Layer, error) {
	_, b.sawParentSession = any(upstream).(netproxy.Session)
	_, b.sawParentCloser = any(upstream).(io.Closer)
	return netproxy.Layer{Data: runtimeTestDataPlane{}}, nil
}

func (b *failingBuilder) Build(*ExtraOption, Upstream) (netproxy.Layer, error) {
	return netproxy.Layer{}, b.err
}

type runtimeTestDataPlane struct{}

type capabilityConn struct{ net.Conn }

func (c *capabilityConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *capabilityConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (c *capabilityConn) SyscallConn() (syscall.RawConn, error)  { return nil, nil }

type capabilityDialer struct{ conn *capabilityConn }

func (d *capabilityDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func (d *capabilityDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return d.conn, nil
}

func (runtimeTestDataPlane) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (runtimeTestDataPlane) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestBuildRuntimeKeepsParentLifecycleOutOfBuilder(t *testing.T) {
	parentDialer := &runtimeTestDialer{state: netproxy.NewStateBroadcaster(netproxy.SessionConnected)}
	builder := new(composingBuilder)
	runtime, err := BuildRuntime(netproxy.Layer{
		Data:      parentDialer,
		Sessions:  []netproxy.Session{parentDialer},
		Resources: []io.Closer{parentDialer},
	}, new(ExtraOption), builder)
	if err != nil {
		t.Fatal(err)
	}
	if builder.sawParentSession || builder.sawParentCloser {
		t.Fatal("builder received the parent's lifecycle capability")
	}
	if runtime.Session() == nil {
		t.Fatal("runtime lost the explicitly declared parent session")
	}
	runtime.Retire()
	if err := runtime.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := parentDialer.closes.Load(); got != 1 {
		t.Fatalf("parent closes = %d, want 1", got)
	}
}

func TestBuildRuntimeClosesAccumulatedChainOnFailure(t *testing.T) {
	wantErr := errors.New("build failed")
	parent := &runtimeTestDialer{state: netproxy.NewStateBroadcaster(netproxy.SessionConnected)}
	if _, err := BuildRuntime(netproxy.Layer{
		Data:      parent,
		Sessions:  []netproxy.Session{parent},
		Resources: []io.Closer{parent},
	}, new(ExtraOption), &failingBuilder{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("BuildRuntime error = %v, want %v", err, wantErr)
	}
	if got := parent.closes.Load(); got != 1 {
		t.Fatalf("parent closes = %d, want 1", got)
	}
}

func TestUpstreamPreservesReturnedConnectionCapabilities(t *testing.T) {
	conn, peer := net.Pipe()
	firstPeer := peer
	t.Cleanup(func() { _ = firstPeer.Close() })
	underlying := &capabilityConn{Conn: conn}
	view := NewUpstream(&capabilityDialer{conn: underlying})
	stream, err := view.DialContext(context.Background(), "udp", "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stream.(syscall.Conn); !ok {
		t.Fatal("stream view hid syscall.Conn")
	}
	if stream != underlying {
		t.Fatal("Upstream replaced the DialContext result")
	}
	if _, ok := stream.(net.PacketConn); !ok {
		t.Fatal("Upstream hid packet methods implemented by the connection")
	}
	_ = stream.Close()

	conn, peer = net.Pipe()
	secondPeer := peer
	t.Cleanup(func() { _ = secondPeer.Close() })
	underlying = &capabilityConn{Conn: conn}
	view = NewUpstream(&capabilityDialer{conn: underlying})
	packet, err := view.ListenPacket(context.Background(), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := packet.(syscall.Conn); !ok {
		t.Fatal("packet view hid syscall.Conn")
	}
	if packet != underlying {
		t.Fatal("Upstream replaced the ListenPacket result")
	}
	if _, ok := packet.(net.Conn); !ok {
		t.Fatal("Upstream hid stream methods implemented by the connection")
	}
	_ = packet.Close()
}

func TestDirectPacketConnInitializesQUICTransportThroughUpstream(t *testing.T) {
	view := NewUpstream(direct.NewDirectDialer(direct.Option{}))
	const remote = "127.0.0.1:9"
	connected, err := view.DialContext(context.Background(), "udp", remote)
	if err != nil {
		t.Fatal(err)
	}
	if connected.RemoteAddr() == nil || connected.RemoteAddr().String() != remote {
		t.Fatalf("DialContext remote = %v, want %s", connected.RemoteAddr(), remote)
	}
	_ = connected.Close()

	packet, err := view.ListenPacket(context.Background(), remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	conn, ok := packet.(net.Conn)
	if !ok {
		t.Fatal("direct packet connection lost its native net.Conn capability")
	}
	if conn.RemoteAddr() != nil {
		t.Fatalf("ListenPacket connected to %v", conn.RemoteAddr())
	}

	transport := &quic.Transport{Conn: packet}
	t.Cleanup(func() { _ = transport.Close() })
	_, err = transport.WriteTo(
		[]byte("probe"),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
	)
	if err != nil {
		t.Fatal(err)
	}
}
