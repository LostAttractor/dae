package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	gun "github.com/daeuniverse/dae/pkg/outbound/pkg/gun_proto"
	grpcapi "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

// The peer uses gRPC's protobuf codec, independently of the client Gun codec.
type peerHunk struct {
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3"`
}

func (h *peerHunk) Reset()         { *h = peerHunk{} }
func (h *peerHunk) String() string { return string(h.Data) }
func (*peerHunk) ProtoMessage()    {}

type peerDialer struct{ listener *bufconn.Listener }

func (d peerDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return d.listener.DialContext(ctx)
}
func (peerDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

func newPeerDialer(t *testing.T, secure bool, handler func(any, grpcapi.ServerStream) error) *Dialer {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	options := []grpcapi.ServerOption{grpcapi.StaticStreamWindowSize(65535)}
	d := &Dialer{ParentDialer: peerDialer{listener}, Address: "passthrough:///peer", ServiceName: "custom"}
	if secure {
		certServer := httptest.NewTLSServer(nil)
		options = append(options, grpcapi.Creds(credentials.NewTLS(&tls.Config{Certificates: certServer.TLS.Certificates})))
		roots := x509.NewCertPool()
		roots.AddCert(certServer.Certificate())
		d.TLSConfig = &tls.Config{RootCAs: roots, ServerName: "example.com"}
		certServer.Close()
	}
	server := grpcapi.NewServer(options...)
	server.RegisterService(&grpcapi.ServiceDesc{ServiceName: "custom", HandlerType: (*interface{})(nil), Streams: []grpcapi.StreamDesc{{StreamName: "Tun", ServerStreams: true, ClientStreams: true, Handler: handler}}}, struct{}{})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	t.Cleanup(func() { d.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if secure && (d.TLSConfig.NextProtos != nil || d.TLSConfig.ServerName != "example.com") {
		t.Fatal("Connect mutated caller TLS configuration")
	}
	return d
}

func TestGunPeerHalfCloseAndReadDeadline(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "plaintext", true: "tls"}[secure], func(t *testing.T) {
			testGunPeerHalfCloseAndReadDeadline(t, secure)
		})
	}
}

func testGunPeerHalfCloseAndReadDeadline(t *testing.T, secure bool) {
	d := newPeerDialer(t, secure, func(_ any, stream grpcapi.ServerStream) error {
		for {
			h := new(peerHunk)
			if err := stream.RecvMsg(h); err != nil {
				if err == io.EOF {
					return stream.SendMsg(&peerHunk{Data: []byte("tail")})
				}
				return err
			}
			if err := stream.SendMsg(h); err != nil {
				return err
			}
		}
	})
	open := func() net.Conn {
		c, err := d.DialContext(context.Background(), "tcp", "target:80")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	first, sibling := open(), open()
	if err := first.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	// A message arriving after the expired Read must remain available after reset.
	if _, err := first.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := first.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(first, got); err != nil || string(got) != "abcdef" {
		t.Fatalf("late data %q %v", got, err)
	}
	if err := first.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(first)
	if err != nil || string(tail) != "tail" {
		t.Fatalf("half-close tail %q %v", tail, err)
	}
	if _, err := first.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after FIN: %v", err)
	}
	if _, err := sibling.Write([]byte("sibling")); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, 7)
	if _, err := io.ReadFull(sibling, got); err != nil || string(got) != "sibling" {
		t.Fatalf("sibling %q %v", got, err)
	}
}

type blockedSend struct {
	started  chan struct{}
	canceled chan struct{}
}

func (*blockedSend) Context() context.Context { return context.Background() }

func (s *blockedSend) Send(*gun.Hunk) error     { close(s.started); <-s.canceled; return context.Canceled }
func (s *blockedSend) Recv() (*gun.Hunk, error) { <-s.canceled; return nil, context.Canceled }
func (*blockedSend) CloseSend() error           { return nil }
func TestWriteDeadlineCancelsOnlyActiveRPC(t *testing.T) {
	tunnel := &blockedSend{started: make(chan struct{}), canceled: make(chan struct{})}
	c := NewClientConn(tunnel, func() { close(tunnel.canceled) })
	channel := netproxy.NewLease(netproxy.NewResourceRef())
	c.lease = channel.NewStream()
	sibling := channel.NewStream()
	t.Cleanup(func() { c.Close() })
	_ = c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Write([]byte("owned")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline %v", err)
	}
	select {
	case <-tunnel.canceled:
	default:
		t.Fatal("timed-out Send still owns a live RPC")
	}
	if c.lease.Valid() || !channel.Valid() || !sibling.Valid() {
		t.Fatal("wrong cancellation scope")
	}
}

// These barriers hold the worker after its real gRPC call has returned. They
// make the Close ordering assertion independent of goroutine scheduling.
type observedTunnel struct {
	gun.Tunnel
	sendStarted, sendReturned, receiveStarted, receiveReturned chan struct{}
	release                                                    chan struct{}
	sends                                                      int
}

func (s *observedTunnel) Send(h *gun.Hunk) error {
	s.sends++
	if s.sends == 1 {
		return s.Tunnel.Send(h)
	}
	close(s.sendStarted)
	err := s.Tunnel.Send(h)
	close(s.sendReturned)
	<-s.release
	return err
}
func (s *observedTunnel) Recv() (*gun.Hunk, error) {
	close(s.receiveStarted)
	h, err := s.Tunnel.Recv()
	close(s.receiveReturned)
	<-s.release
	return h, err
}

func TestCloseJoinsBlockedGRPCWorkers(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "plaintext", true: "tls"}[secure], func(t *testing.T) {
			peerStarted := make(chan struct{})
			d := newPeerDialer(t, secure, func(_ any, stream grpcapi.ServerStream) error {
				close(peerStarted)
				// No RecvMsg: the stream's HTTP/2 receive window never reopens.
				<-stream.Context().Done()
				return stream.Context().Err()
			})
			handle, err := d.session().CurrentHandle()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			tun, err := gun.Open(ctx, handle.Resource(), "custom")
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			observed := &observedTunnel{Tunnel: tun, sendStarted: make(chan struct{}), sendReturned: make(chan struct{}), receiveStarted: make(chan struct{}), receiveReturned: make(chan struct{}), release: make(chan struct{})}
			c := NewClientConn(observed, cancel)
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(observed.release) }) }
			t.Cleanup(func() { release(); c.Close() })
			wait := func(ch <-chan struct{}, operation string) {
				t.Helper()
				select {
				case <-ch:
				case <-time.After(time.Second):
					t.Fatalf("%s blocked", operation)
				}
			}
			wait(peerStarted, "peer start")
			wait(observed.receiveStarted, "Recv start")
			// The first large message fills the send quota. The next must wait
			// for the peer to consume data, which this peer deliberately never does.
			if _, err := c.Write(make([]byte, 1<<20)); err != nil {
				t.Fatal(err)
			}
			writeResult := make(chan error, 1)
			go func() { _, err := c.Write(make([]byte, 1<<20)); writeResult <- err }()
			wait(observed.sendStarted, "Send start")
			select {
			case <-observed.sendReturned:
				t.Fatal("Send was not blocked by flow control")
			case <-observed.receiveReturned:
				t.Fatal("Recv returned without peer data")
			case <-time.After(10 * time.Millisecond):
			}
			closed := make(chan struct{})
			go func() { c.Close(); close(closed) }()
			wait(observed.sendReturned, "cancel Send")
			wait(observed.receiveReturned, "cancel Recv")
			select {
			case <-closed:
				t.Fatal("Close returned before both workers released the tunnel")
			case <-time.After(10 * time.Millisecond):
			}
			release()
			wait(closed, "Close worker join")
			select {
			case err := <-writeResult:
				if err == nil {
					t.Fatal("blocked Write succeeded after Close")
				}
			case <-time.After(time.Second):
				t.Fatal("Close did not release Write")
			}
		})
	}
}
