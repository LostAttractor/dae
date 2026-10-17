// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"io"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type upstreamDial struct {
	dialer                  *dialer.Dialer
	path                    stats.Path
	origin                  netproxy.FailureOrigin
	resource, policy, route *netproxy.Lease
	abort                   func()
}

func newUpstreamDial(option *DialOption) upstreamDial {
	path, _ := option.trafficAttribution()
	d := upstreamDial{dialer: option.Dialer, path: path, policy: option.PolicyLease}
	if option.Direct {
		d.origin = netproxy.OriginTarget
	}
	return d
}

// A setup error can reach relay error handling (notably a UDP destination
// socket). Preserve its classification without reporting the same failure twice.
type upstreamDialError struct {
	error
	reportable bool
}

func (e *upstreamDialError) Unwrap() error { return e.error }

// establishUpstream owns setup deadlines, lease aborts and accounting for every
// transport. Only successful establishment contributes a dial-duration sample.
func (d upstreamDial) establishUpstream[C io.Closer](parent context.Context, open func(context.Context) (C, error)) (C, error) {
	var zero C
	ctx, cancel := context.WithTimeout(parent, consts.DefaultDialTimeout)
	defer cancel()
	abort := func() {
		cancel()
		if d.abort != nil {
			d.abort()
		}
	}
	stop := watchAbort(d.resource, d.policy, d.route, abort)
	defer stop()
	if cause := connectionAbortCause(d.resource, d.policy, d.route); cause != nil {
		abort()
		return zero, &upstreamDialError{error: cause}
	}
	if err := ctx.Err(); err != nil {
		return zero, &upstreamDialError{error: err}
	}
	started := time.Now()
	conn, err := open(ctx)
	if cause := connectionAbortCause(d.resource, d.policy, d.route); cause != nil {
		abort()
		closeInBackground(conn)
		return zero, &upstreamDialError{error: cause}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		closeInBackground(conn)
		err = netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpDial, Origin: d.origin})
		failure := &upstreamDialError{error: err}
		if parent.Err() == nil {
			failure.reportable = recordDataPlaneError(d.dialer, d.path, err)
		}
		return zero, failure
	}
	stats.DefaultStore.RecordDial(d.path, time.Since(started))
	return conn, nil
}
