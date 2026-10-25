package singmux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	grpctransport "github.com/daeuniverse/dae/pkg/outbound/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// gunHunk is the Gun wire message: protobuf field 1 carries the bytes.
type gunHunk struct {
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3"`
}

func (h *gunHunk) Reset()         { *h = gunHunk{} }
func (h *gunHunk) String() string { return string(h.Data) }
func (*gunHunk) ProtoMessage()    {}

// gunConn is the server end of one Gun RPC. Close ends the RPC.
type gunConn struct {
	grpc.ServerStream
	buf   []byte
	done  chan struct{}
	close func()
}

func (c *gunConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		h := new(gunHunk)
		if err := c.RecvMsg(h); err != nil {
			return 0, err
		}
		c.buf = h.Data
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *gunConn) Write(p []byte) (int, error) {
	if err := c.SendMsg(&gunHunk{Data: p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *gunConn) Close() error                   { c.close(); return nil }
func (*gunConn) LocalAddr() net.Addr              { return nil }
func (*gunConn) RemoteAddr() net.Addr             { return nil }
func (*gunConn) SetDeadline(time.Time) error      { return nil }
func (*gunConn) SetReadDeadline(time.Time) error  { return nil }
func (*gunConn) SetWriteDeadline(time.Time) error { return nil }

type bufconnDialer struct{ listener *bufconn.Listener }

func (d bufconnDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return d.listener.DialContext(ctx)
}
func (bufconnDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

// serveGun is a minimal Gun server in memory; every RPC carries one sing-mux
// session, served as by serveSingMux. It returns the gRPC client dialer.
func serveGun(t *testing.T, protocol Protocol, handle func(muxRequest, net.Conn)) netproxy.Dialer {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "GunService", HandlerType: (*any)(nil), Streams: []grpc.StreamDesc{{
		StreamName: "Tun", ServerStreams: true, ClientStreams: true,
		Handler: func(_ any, stream grpc.ServerStream) error {
			done := make(chan struct{})
			conn := &gunConn{ServerStream: stream, done: done, close: sync.OnceFunc(func() { close(done) })}
			go func() {
				defer conn.Close()
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil || header[1] != byte(protocol) {
					return
				}
				serveStreams(t, protocol, conn, handle)
			}()
			select {
			case <-done:
			case <-stream.Context().Done():
			}
			return nil
		},
	}}}, nil)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	dialer := &grpctransport.Dialer{ParentDialer: bufconnDialer{listener}, Address: "passthrough:///gun"}
	t.Cleanup(func() { _ = dialer.Close() })
	if err := dialer.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	return dialer
}

// A stream's last upload, then its Close and at once the session's, as on a
// retired path: the server reads all of it and EOF over a carrier that
// writes synchronously (a pipe) and one that queues (gRPC, whose Close
// cancels the RPC with what it queued). The peer's EOF that ends the
// session after its carrier is half-closed is local cleanup, not a failure.
func TestSessionCloseDeliversLastUpload(t *testing.T) {
	const size = 256 << 10
	for _, protocol := range []Protocol{ProtocolSmux, ProtocolYAMux} {
		for _, carrier := range []string{"pipe", "grpc"} {
			t.Run(protocol.String()+"/"+carrier, func(t *testing.T) {
				results := make(chan error, 1)
				handle := func(_ muxRequest, stream net.Conn) {
					if _, err := stream.Write([]byte{1}); err != nil {
						results <- err
						return
					}
					// The target closes first where the stream can say so.
					_ = netproxy.CloseWrite(stream)
					_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
					data, err := io.ReadAll(stream)
					if err == nil && len(data) != size {
						err = fmt.Errorf("server read %d of %d bytes", len(data), size)
					}
					results <- err
				}
				var dialer netproxy.Dialer
				if carrier == "pipe" {
					dialer = serveSingMux(t, protocol, handle)
				} else {
					dialer = serveGun(t, protocol, handle)
				}
				for range 20 {
					mux := &Mux{Dialer: dialer, Protocol: protocol, MaxConnections: 1}
					if err := mux.Connect(t.Context()); err != nil {
						t.Fatal(err)
					}
					pool := mux.pool()
					pool.mu.Lock()
					lifecycle := pool.slots[0].lifecycle
					pool.mu.Unlock()
					conn, err := mux.DialContext(t.Context(), "tcp", "example.com:80")
					if err != nil {
						t.Fatal(err)
					}
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					// The first byte carries the stream request; the reply
					// shows the server accepted the stream.
					if _, err := conn.Write([]byte{0}); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
						t.Fatal(err)
					}
					if _, err := conn.Write(make([]byte, size-1)); err != nil {
						t.Fatal(err)
					}
					_ = netproxy.CloseWrite(conn)
					_ = conn.Close()
					_ = mux.Close()
					select {
					case err := <-results:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(4 * time.Second):
						t.Fatal("server never finished the stream")
					}
					if state := lifecycle.Snapshot(); state.EpisodeID != 0 {
						t.Fatalf("closing the session recorded a failure: %+v", state)
					}
				}
			})
		}
	}
}

// silentPeerConn half-closes as a carrier that can, but its peer never
// answers with EOF.
type silentPeerConn struct{ net.Conn }

func (silentPeerConn) CloseWrite() error                  { return nil }
func (c silentPeerConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

// A session whose peer reads but never answers closes after
// netproxy.CloseLinger.
func TestSessionCloseWaitIsBounded(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolSmux, ProtocolYAMux} {
		synctest.Test(t, func(t *testing.T) {
			parent := &pipeDialer{server: make(chan net.Conn), wrapClient: func(_ int, conn net.Conn) net.Conn { return silentPeerConn{conn} }}
			go func() {
				for conn := range parent.server {
					go func() { _, _ = io.Copy(io.Discard, conn) }()
				}
			}()
			defer close(parent.server)
			mux := &Mux{Dialer: parent, Protocol: protocol, MaxConnections: 1}
			if err := mux.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			_ = mux.Close()
			if waited := time.Since(start); waited != netproxy.CloseLinger {
				t.Fatalf("%s: Close took %v, want %v", protocol, waited, netproxy.CloseLinger)
			}
		})
	}
}

// halfClosingConn fails writes after CloseWrite, as TCP and gRPC carriers
// do, and reports the half-close.
type halfClosingConn struct {
	net.Conn
	halfClosed chan struct{}
}

func (c halfClosingConn) CloseWrite() error { close(c.halfClosed); return nil }

func (c halfClosingConn) Write(p []byte) (int, error) {
	select {
	case <-c.halfClosed:
		return 0, net.ErrClosed
	default:
		return c.Conn.Write(p)
	}
}

// A ping that reaches a closing yamux session after its carrier is
// half-closed, such as a keepalive, does not end the wait for the peer's
// EOF: writing the pong would fail the carrier, and closing a gRPC carrier
// then cancels what it still queues.
func TestYamuxCloseIgnoresPingAfterHalfClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		halfClosed, peerDone := make(chan struct{}), make(chan struct{})
		parent := &pipeDialer{server: make(chan net.Conn), wrapClient: func(_ int, conn net.Conn) net.Conn { return halfClosingConn{conn, halfClosed} }}
		go func() {
			conn := <-parent.server
			defer conn.Close()
			if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
				return
			}
			for header := make([]byte, 12); ; {
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				if header[1] == 3 { // GoAway
					break
				}
				if header[1] == 0 { // data
					_, _ = io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint32(header[8:])))
				}
			}
			<-halfClosed
			// Ping, flag SYN, stream 0.
			_, _ = conn.Write([]byte{0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})
			<-peerDone
		}()
		mux := &Mux{Dialer: parent, Protocol: ProtocolYAMux, MaxConnections: 1}
		if err := mux.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		closed := make(chan struct{})
		go func() { defer close(closed); _ = mux.Close() }()
		// The peer leaves on failure too, so that the bubble can end.
		leave := sync.OnceFunc(func() { close(peerDone) })
		defer leave()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("a pong after the half-close ended the wait for the peer's EOF")
		default:
		}
		leave()
		<-closed
	})
}

// A stream closed after a closing session half-closed its carrier, as a
// relay does once its writes fail on the closing session, does not end the
// wait for the peer's EOF: its FIN would fail the carrier, and closing a
// gRPC carrier then cancels what it still queues.
func TestSessionCloseIgnoresStreamCloseAfterHalfClose(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolSmux, ProtocolYAMux} {
		synctest.Test(t, func(t *testing.T) {
			halfClosed, peerDone := make(chan struct{}), make(chan struct{})
			parent := &pipeDialer{server: make(chan net.Conn), wrapClient: func(_ int, conn net.Conn) net.Conn { return halfClosingConn{conn, halfClosed} }}
			go func() {
				conn := <-parent.server
				defer conn.Close()
				go func() { _, _ = io.Copy(io.Discard, conn) }()
				<-peerDone
			}()
			mux := &Mux{Dialer: parent, Protocol: protocol, MaxConnections: 1}
			if err := mux.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			open, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := open.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
			closed := make(chan struct{})
			go func() { defer close(closed); _ = mux.Close() }()
			// The peer leaves on failure too, so that the bubble can end.
			leave := sync.OnceFunc(func() { close(peerDone) })
			defer leave()
			<-halfClosed
			_ = open.Close()
			synctest.Wait()
			select {
			case <-closed:
				t.Fatalf("%s: a stream closed after the half-close ended the wait for the peer's EOF", protocol)
			default:
			}
			leave()
			<-closed
		})
	}
}
