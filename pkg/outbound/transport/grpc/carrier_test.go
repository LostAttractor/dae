package grpc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	grpcapi "google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type leasedCarrierConn struct {
	net.Conn
	lease     *netproxy.Lease
	closeWait <-chan struct{}
}

func (c *leasedCarrierConn) Close() error {
	if c.closeWait != nil {
		<-c.closeWait
	}
	return c.Conn.Close()
}

func (c *leasedCarrierConn) DependencyLease() *netproxy.Lease { return c.lease }

type leasedCarrierParent struct {
	listener  *bufconn.Listener
	lease     *netproxy.Lease
	opened    chan net.Conn
	closeWait <-chan struct{}
}

func (p leasedCarrierParent) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	c, e := p.listener.DialContext(ctx)
	if e != nil {
		return nil, e
	}
	if p.opened != nil {
		select {
		case p.opened <- c:
		case <-ctx.Done():
			_ = c.Close()
			return nil, ctx.Err()
		}
	}
	return &leasedCarrierConn{Conn: c, lease: p.lease, closeWait: p.closeWait}, nil
}
func (leasedCarrierParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	panic("unexpected")
}
func TestGRPCCarrierTermination(t *testing.T) {
	for _, action := range []string{"parent_abort", "socket_failure", "local_close"} {
		t.Run(action, func(t *testing.T) {
			listener, server := carrierPeer(t, "ready")
			defer server.Stop()
			parent := netproxy.NewLease(netproxy.NewResourceRef())
			opened := make(chan net.Conn, 1)
			closeWait := make(chan struct{})
			parentDialer := leasedCarrierParent{listener: listener, lease: parent, opened: opened}
			if action == "parent_abort" {
				parentDialer.closeWait = closeWait
			}
			d := &Dialer{ParentDialer: parentDialer, Address: "passthrough:///peer", ServiceName: "custom"}
			defer d.Close()
			defer close(closeWait)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := d.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialContext(ctx, "tcp", "192.0.2.1:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			lease := netproxy.DependencyOf(conn)
			physical := <-opened
			switch action {
			case "parent_abort":
				cause := netproxy.WrapFailure(errors.New("physical parent failed"), netproxy.Failure{Layer: netproxy.LayerSMUX, Scope: netproxy.ScopeStream, Reason: netproxy.ReasonReset})
				parent.Abort(cause)
				if !errors.Is(lease.AbortCause(), cause) {
					t.Fatal("parent abort did not propagate synchronously")
				}
				// Parent Close is still blocked. Session admission must already stop.
				for d.Snapshot().Accepting && ctx.Err() == nil {
					time.Sleep(time.Millisecond)
				}
				if d.Snapshot().Accepting {
					t.Fatal("failed carrier remained accepting during cleanup")
				}
				if fact := netproxy.ClassifyFailure(d.Snapshot().Cause); fact.Scope != netproxy.ScopeSharedResource || fact.Resource != lease.Resource() {
					t.Fatalf("channel failure lost carrier ownership: %+v", fact)
				}
			case "socket_failure":
				_ = physical.Close()
				select {
				case <-lease.Done():
				case <-ctx.Done():
					t.Fatal("socket failure did not revoke dependent streams")
				}
				if lease.AbortCause() == nil {
					t.Fatal("socket failure lost Abort")
				}
			case "local_close":
				_ = d.Close()
				if lease.Valid() || lease.AbortCause() != nil {
					t.Fatal("local shutdown issued an abort or retained a live lease")
				}
			}
		})
	}
}

func carrierPeer(t *testing.T, payload string) (*bufconn.Listener, *grpcapi.Server) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpcapi.NewServer()
	server.RegisterService(&grpcapi.ServiceDesc{ServiceName: "custom", HandlerType: (*interface{})(nil), Streams: []grpcapi.StreamDesc{{StreamName: "Tun", ServerStreams: true, ClientStreams: true, Handler: func(_ any, s grpcapi.ServerStream) error {
		if err := s.SendMsg(&peerHunk{Data: []byte(payload)}); err != nil {
			return err
		}
		<-s.Context().Done()
		return s.Context().Err()
	}}}}, struct{}{})
	go server.Serve(listener)
	t.Cleanup(func() { _ = listener.Close() })
	return listener, server
}

type replacementCarrierParent struct {
	first, second leasedCarrierParent
	calls         atomic.Int32
}

func (p *replacementCarrierParent) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if p.calls.Add(1) == 1 {
		return p.first.DialContext(ctx, network, address)
	}
	return p.second.DialContext(ctx, network, address)
}
func (*replacementCarrierParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}

func TestGRPCDrainingCarrierDoesNotAbortReplacementStreams(t *testing.T) {
	firstListener, firstServer := carrierPeer(t, "old")
	defer firstServer.Stop()
	secondListener, secondServer := carrierPeer(t, "new")
	defer secondServer.Stop()
	firstLease, secondLease := netproxy.NewLease(netproxy.NewResourceRef()), netproxy.NewLease(netproxy.NewResourceRef())
	d := &Dialer{Address: "passthrough:///peer", ServiceName: "custom", ParentDialer: &replacementCarrierParent{
		first:  leasedCarrierParent{listener: firstListener, lease: firstLease},
		second: leasedCarrierParent{listener: secondListener, lease: secondLease},
	}}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	old, err := d.DialContext(ctx, "tcp", "target:443")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	buf := make([]byte, 3)
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(old, buf); err != nil || string(buf) != "old" {
		t.Fatalf("old RPC = %q, %v", buf, err)
	}
	original := d.carrier.Load()
	go firstServer.GracefulStop()
	for (d.carrier.Load() == original || !d.Snapshot().Accepting) && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("gRPC did not replace its draining carrier without another Connect request")
	}
	fresh, err := d.DialContext(ctx, "tcp", "target:443")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if !netproxy.DependencyOf(old).Valid() {
		t.Fatal("GOAWAY invalidated a still-draining RPC")
	}
	firstLease.Abort(errors.New("old carrier failed while draining"))
	if netproxy.DependencyOf(old).AbortCause() == nil || !netproxy.DependencyOf(fresh).Valid() {
		t.Fatal("abort crossed physical carrier boundaries")
	}
	_ = fresh.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(fresh, buf); err != nil || string(buf) != "new" {
		t.Fatalf("replacement RPC = %q, %v", buf, err)
	}
	if !d.Snapshot().Accepting {
		t.Fatal("old carrier failure invalidated the replacement channel")
	}
}

func TestGRPCParentInvalidationRecoversAfterOwnerClose(t *testing.T) {
	firstListener, firstServer := carrierPeer(t, "old")
	defer firstServer.Stop()
	secondListener, secondServer := carrierPeer(t, "new")
	defer secondServer.Stop()
	firstLease, secondLease := netproxy.NewLease(netproxy.NewResourceRef()), netproxy.NewLease(netproxy.NewResourceRef())
	opened := make(chan net.Conn, 1)
	d := &Dialer{Address: "passthrough:///peer", ServiceName: "custom", ParentDialer: &replacementCarrierParent{
		first:  leasedCarrierParent{listener: firstListener, lease: firstLease, opened: opened},
		second: leasedCarrierParent{listener: secondListener, lease: secondLease},
	}}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	old, err := d.DialContext(ctx, "tcp", "target:443")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	original := d.carrier.Load()
	firstLease.Invalidate(errors.New("parent stopped admitting work"))
	for d.Snapshot().Accepting && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("parent invalidation did not stop admission")
	}
	if _, err := d.DialContext(ctx, "tcp", "target:443"); !errors.Is(err, netproxy.ErrNotConnected) {
		t.Fatalf("invalidated carrier admitted new work: %v", err)
	}
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	if data, err := io.ReadAll(io.LimitReader(old, 3)); err != nil || string(data) != "old" {
		t.Fatalf("draining RPC: %q, %v", data, err)
	}
	if netproxy.DependencyOf(old).AbortCause() != nil {
		t.Fatal("parent invalidation aborted the draining RPC")
	}
	// The parent owner ends its draining carrier; library-managed recovery
	// must proceed without another Connect request from the daemon.
	_ = (<-opened).Close()
	for (d.carrier.Load() == original || !d.Snapshot().Accepting) && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("gRPC did not recover after the parent owner closed its carrier")
	}
	fresh, err := d.DialContext(ctx, "tcp", "target:443")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	_ = fresh.SetReadDeadline(time.Now().Add(time.Second))
	if data, err := io.ReadAll(io.LimitReader(fresh, 3)); err != nil || string(data) != "new" {
		t.Fatalf("replacement RPC: %q, %v", data, err)
	}
	if !netproxy.DependencyOf(fresh).Valid() {
		t.Fatal("replacement RPC retained the failed parent dependency")
	}
}

func TestCompletedRPCIgnoresLaterCarrierFailure(t *testing.T) {
	finished := make(chan struct{})
	d := newPeerDialer(t, false, func(_ any, stream grpcapi.ServerStream) error {
		if err := stream.SendMsg(&peerHunk{Data: []byte("ready")}); err != nil {
			return err
		}
		<-finished
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "target:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if data, err := io.ReadAll(io.LimitReader(conn, 5)); err != nil || string(data) != "ready" {
		t.Fatalf("RPC initial data: %q, %v", data, err)
	}
	close(finished)
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("completed RPC: %v", err)
	}
	// The completed RPC keeps its graceful result even before user Close.
	if err := d.carrier.Load().Close(); err != nil {
		t.Fatal(err)
	}
	if cause := netproxy.DependencyOf(conn).AbortCause(); cause != nil {
		t.Fatalf("completed RPC received carrier abort: %v", cause)
	}
}
