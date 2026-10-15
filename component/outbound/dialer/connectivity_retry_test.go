// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

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
