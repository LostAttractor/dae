// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Reconnecting a failed path publishes its own session transitions. They are
// the attempt's outcome rather than new evidence, so a path that stays
// unreachable keeps backing off instead of reconnecting back to back.
func TestUnreachablePathReconnectKeepsBackoff(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	prepareRecoveryDialer(d)
	const backoff = 25 * time.Millisecond
	d.CheckIntervalMax = backoff
	transport.connectErr = errors.New("unreachable")
	checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error { return nil })
	start := make(chan struct{})
	var worker sync.WaitGroup
	worker.Go(func() { checker.run(start) })
	t.Cleanup(func() {
		_ = d.Close()
		worker.Wait()
	})
	close(start)
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("carrier reset"))

	const window = 10 * backoff
	time.Sleep(window)
	// Each retry waits at least 80% of the capped backoff.
	if connects := transport.connects.Load(); connects > int32(window/(backoff*4/5))+1 {
		t.Fatalf("unreachable path reconnected %d times in %v; backoff was bypassed", connects, window)
	}
}

func TestSecondHealthProbeAuthBlocksRetry(t *testing.T) {
	d := newTestDialer(t, authProxyParent{})
	prepareRecoveryDialer(d)
	auth := netproxy.WrapFailure(errors.New("authentication rejected"), netproxy.Failure{
		Scope: netproxy.ScopeStream, Layer: netproxy.LayerH2,
		Origin: netproxy.OriginPeer, Reason: netproxy.ReasonAuth,
	})
	calls := 0
	checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
		calls++
		if calls == 1 {
			return io.ErrUnexpectedEOF
		}
		return auth
	})
	defer checker.stopRetries()
	result := checker.performAttempt(t.Context(), d.beginConnectivityCheck(checkHealth))
	checker.cancel = func() {}
	finishCheck(checker, result)
	if calls != 2 || checker.blockedBy != "auth" || !d.RuntimeStatus().Recovery.RetryAt.IsZero() {
		t.Fatalf("second auth lost: calls=%d blocked=%q retained_failure=%v recovery=%+v", calls, checker.blockedBy, result.failure(), d.RuntimeStatus().Recovery)
	}
}
