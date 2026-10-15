package common

import (
	"errors"
	"io"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

// IsCapacityError describes admission pressure, not a failed QUIC connection.
func IsCapacityError(err error) bool {
	var limit quic.StreamLimitReachedError
	return errors.As(err, &limit) || errors.Is(err, ErrTooManyOpenStreams) || errors.Is(err, ErrHoldOn)
}

// WrapQUICError keeps the original error and the exact resource that produced it.
// A stream reset must never invalidate its parent connection.
func WrapQUICError(err error, ref netproxy.ResourceRef, lease *netproxy.Lease, op netproxy.Operation, fail func(error)) error {
	if err == nil || err == io.EOF && op == netproxy.OpRead {
		return err
	}
	var causes []error
	for _, failure := range netproxy.Failures(err) {
		cause := failure.Cause
		failure.Resource, failure.Phase = ref, op
		if failure.Layer == netproxy.LayerUnknown {
			failure.Layer = netproxy.LayerQUIC
		}
		if lease != nil {
			failure.Stream = lease.Stream()
		}
		// These admission sentinels belong to this pool, beyond QUIC's typed limit.
		if errors.Is(cause, ErrTooManyOpenStreams) || errors.Is(cause, ErrHoldOn) {
			failure.Scope, failure.Reason = netproxy.ScopeOperation, netproxy.ReasonCapacity
		}
		if failure.Origin == netproxy.OriginLocalProtocol && lease != nil && !lease.Valid() {
			if cleanup := netproxy.ClassifyFailure(lease.Cause()); cleanup.Origin == netproxy.OriginLocalCleanup {
				failure.Origin, failure.Reason = netproxy.OriginLocalCleanup, netproxy.ReasonClosed
			}
		}
		wrapped := netproxy.WrapFailure(cause, failure)
		if failure.Scope == netproxy.ScopeSharedResource {
			if fail != nil {
				fail(wrapped)
			}
		} else if failure.Scope == netproxy.ScopeStream && lease != nil {
			lease.Invalidate(wrapped)
		}
		causes = append(causes, wrapped)
	}
	if len(causes) == 1 {
		return causes[0]
	}
	return errors.Join(causes...)
}
