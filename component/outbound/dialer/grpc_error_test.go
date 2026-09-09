package dialer

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	grpctransport "github.com/daeuniverse/outbound/transport/grpc"
)

type failingGRPCParent struct {
	testTransport
	cause error
}

func (p failingGRPCParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, p.cause
}

func TestGRPCInitialFailureDiagnosisAndRetryPolicy(t *testing.T) {
	auth := netproxy.WrapFailure(errors.New("proxy authentication rejected"), netproxy.Failure{
		Layer: netproxy.LayerProxy, Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonAuth, Origin: netproxy.OriginPeer,
	})
	for _, tc := range []struct {
		name    string
		cause   error
		blocked bool
	}{
		{"authentication", auth, true},
		{"authentication with deadline", errors.Join(auth, context.DeadlineExceeded), true},
		{"TCP refusal", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
		{"deadline only", context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &grpcRetryTransport{Dialer: &grpctransport.Dialer{
				ParentDialer: failingGRPCParent{cause: tc.cause}, Address: "passthrough:///peer",
			}}
			d := newTestDialer(t, transport)
			checker := testRecoveryChecker(t, d)
			checker.start(checkInitial)
			var result checkResult
			select {
			case result = <-checker.results:
			case <-time.After(3 * time.Second):
				t.Fatal("Connect did not finish")
			}
			for _, err := range []error{result.connectErr, transport.Snapshot().Cause} {
				if !errors.Is(err, tc.cause) || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost parent error or deadline: %v", err)
				}
			}
			checker.handleSessionEvent(transport.Snapshot())
			if !finishCheck(checker, result) {
				t.Fatal("checker stopped")
			}
			status := d.RuntimeStatus()
			if tc.blocked {
				if status.Recovery.Phase != RecoveryBlocked || status.Recovery.BlockedBy != "auth" || !status.Recovery.RetryAt.IsZero() {
					t.Fatalf("authentication should block retries: %+v", status)
				}
			} else if status.Recovery.Phase != RecoveryBackoff || status.Recovery.RetryAt.IsZero() {
				t.Fatalf("transient failure should retry: %+v", status)
			}
		})
	}
}
