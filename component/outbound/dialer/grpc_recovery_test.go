package dialer

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	grpctransport "github.com/daeuniverse/outbound/transport/grpc"
	grpcapi "google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type grpcRetryParent struct {
	testTransport
	listener  *bufconn.Listener
	available atomic.Bool
}

func (p *grpcRetryParent) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if !p.available.Load() {
		return nil, syscall.ECONNREFUSED
	}
	return p.listener.DialContext(ctx)
}

type grpcRetryTransport struct {
	*grpctransport.Dialer
	connects atomic.Int32
}

func (d *grpcRetryTransport) Connect(parent context.Context) error {
	d.connects.Add(1)
	ctx, cancel := context.WithTimeout(parent, 250*time.Millisecond)
	defer cancel()
	return d.Dialer.Connect(ctx)
}

func TestGRPCInitialFailureRetriesUntilServerRecovers(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	defer listener.Close()
	server := grpcapi.NewServer()
	defer server.Stop()
	go server.Serve(listener)
	parent := &grpcRetryParent{listener: listener}
	transport := &grpcRetryTransport{Dialer: &grpctransport.Dialer{
		ParentDialer: parent, Address: "passthrough:///peer",
	}}
	d := newTestDialer(t, transport)
	d.CheckIntervalMax = 100 * time.Millisecond
	checker := testRecoveryChecker(t, d)
	start, done := make(chan struct{}), make(chan struct{})
	close(start)
	go func() {
		checker.run(start)
		close(done)
	}()
	defer func() {
		_ = d.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("checker did not stop")
		}
	}()

	state := waitRecoveryPhase(t, d, RecoveryBackoff)
	if state.Executor != netproxy.RecoveryDaemon || state.RetryAt.IsZero() || d.RuntimeStatus().Healthy {
		t.Fatalf("initial failure must retain a daemon retry: %+v", state)
	}
	// Start accepting transports without requesting another check or reloading.
	parent.available.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status := d.RuntimeStatus()
		if status.Healthy && status.InitialCheckDone && status.Recovery.Phase == RecoveryBackoff && status.Recovery.Action == "verify" {
			if transport.connects.Load() < 2 || status.Session.RecoveryExecutor != netproxy.RecoveryLibraryManaged || !status.Recovery.RetryAt.After(time.Now()) || !status.Degraded {
				t.Fatalf("recovered channel: %+v", status)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("server recovered but node did not: %+v", d.RuntimeStatus())
}
