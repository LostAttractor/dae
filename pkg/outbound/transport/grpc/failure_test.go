package grpc

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	proto "github.com/daeuniverse/dae/pkg/outbound/pkg/gun_proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type failedTunnel struct {
	err error
}

func (*failedTunnel) Context() context.Context { return context.Background() }

func (s *failedTunnel) Recv() (*proto.Hunk, error) { return nil, s.err }
func (s *failedTunnel) Send(*proto.Hunk) error     { return s.err }
func (s *failedTunnel) CloseSend() error           { return s.err }

func TestRPCStatusNeverBecomesSuccessfulEOF(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.OutOfRange} {
		for _, operation := range []string{"read", "write", "close_write"} {
			t.Run(code.String()+"/"+operation, func(t *testing.T) {
				original := status.Error(code, "original peer detail")
				conn := NewClientConn(&failedTunnel{err: original}, func() {})
				channel := netproxy.NewLease(netproxy.ResourceRef{})
				conn.lease = channel.NewStream()
				sibling := channel.NewStream()
				defer conn.Close()
				var err error
				switch operation {
				case "read":
					_, err = conn.Read(make([]byte, 8))
				case "write":
					_, err = conn.Write([]byte("request"))
				case "close_write":
					err = conn.CloseWrite()
				}
				if err == nil || errors.Is(err, io.EOF) || status.Code(err) != code || !errors.Is(err, original) {
					t.Fatalf("lost RPC status: %v", err)
				}
				fact := netproxy.ClassifyFailure(err)
				if fact.Scope != netproxy.ScopeStream || fact.Layer != netproxy.LayerGRPC || fact.Resource != (netproxy.ResourceRef{}) {
					t.Fatalf("invented transport identity/scope: %+v", fact)
				}
				if !channel.Valid() || !sibling.Valid() {
					t.Fatal("RPC error invalidated logical channel/sibling")
				}
			})
		}
	}
}

func TestNormalRPCReadEOFAndExplicitCleanupAreDistinct(t *testing.T) {
	conn := NewClientConn(&failedTunnel{err: io.EOF}, func() {})
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("normal Read EOF=%v", err)
	}
	if _, err := conn.Write([]byte("x")); err == io.EOF || !errors.Is(err, io.EOF) {
		t.Fatalf("Write EOF must retain failure wrapper: %v", err)
	}
	_ = conn.Close()
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) || netproxy.ClassifyFailure(err).Origin != netproxy.OriginLocalCleanup {
		t.Fatalf("local cleanup lacks evidence: %v", err)
	}
}
