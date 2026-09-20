package control

import (
	"context"
	"net"
	"net/http"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/outbound/netproxy"
)

// Keep the accepted connection's lifetime across per-request route plans.
// The pinned original policy and actual upstream resources can terminate it.
func mitmPlannerWithLease(planner mitm.UpstreamPlanner, lease *netproxy.Lease) mitm.UpstreamPlanner {
	return func(request *http.Request) (mitm.UpstreamPlan, error) {
		if cause := lease.AbortCause(); cause != nil {
			return mitm.UpstreamPlan{}, cause
		}
		plan, err := planner(request)
		if err != nil {
			return plan, err
		}
		if check := plan.Check; check != nil {
			plan.Check = func() error {
				if cause := check(); cause != nil {
					lease.Abort(cause)
					return cause
				}
				return lease.AbortCause()
			}
		}
		if dial := plan.Dial; dial != nil {
			plan.Dial = func(parent context.Context, network, address string) (net.Conn, error) {
				ctx, cancel := context.WithCancel(parent)
				defer cancel()
				stop := watchAbort(lease, nil, nil, cancel)
				defer stop()
				if cause := lease.AbortCause(); cause != nil {
					return nil, cause
				}
				conn, err := dial(ctx, network, address)
				if cause := lease.AbortCause(); cause != nil {
					closeInBackground(conn)
					return nil, cause
				}
				if err == nil {
					bindMITMDependency(lease, conn)
				}
				return conn, err
			}
		}
		if dial := plan.DialPacket; dial != nil {
			plan.DialPacket = func(parent context.Context, address string) (net.PacketConn, net.Addr, error) {
				ctx, cancel := context.WithCancel(parent)
				defer cancel()
				stop := watchAbort(lease, nil, nil, cancel)
				defer stop()
				if cause := lease.AbortCause(); cause != nil {
					return nil, nil, cause
				}
				conn, peer, err := dial(ctx, address)
				if cause := lease.AbortCause(); cause != nil {
					closeInBackground(conn)
					return nil, nil, cause
				}
				if err == nil {
					bindMITMDependency(lease, conn)
				}
				return conn, peer, err
			}
		}
		return plan, nil
	}
}

func bindMITMDependency(client *netproxy.Lease, conn any) {
	dependency := netproxy.DependencyOf(conn)
	if dependency == nil {
		return
	}
	go func() {
		select {
		case <-dependency.Done():
			if cause := dependency.AbortCause(); cause != nil {
				client.Abort(cause)
			}
		case <-client.Done():
		}
	}()
}
