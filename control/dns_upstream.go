// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
)

// DNS transports share the data plane's accounting and resource/policy leases.
// The plugin owns the connection and must close it before its invocation ends.
func (c *ControlPlane) dnsDialLifetime(parent context.Context, option *DialOption, identity routingResult) (context.Context, context.CancelFunc, *netproxy.Lease, func(), error) {
	route, err := c.deviceRoutes.acquire(&identity)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	release, err := option.Dialer.Retain()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(parent, consts.DefaultDialTimeout)
	stop := watchAbort(nil, option.PolicyLease, route, cancel)
	cleanup := func() { stop(); cancel() }
	if cause := connectionAbortCause(option.PolicyLease, route); cause != nil {
		cleanup()
		release()
		return nil, nil, nil, nil, cause
	}
	return ctx, cleanup, route, release, nil
}

func (c *ControlPlane) dialDNSUpstream(parent context.Context, network string, option *DialOption, identity routingResult) (net.Conn, error) {
	ctx, cleanup, route, release, err := c.dnsDialLifetime(parent, option, identity)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	started := time.Now()
	conn, err := option.dialerForConnection().DialContext(ctx, network, option.DialTarget)
	if cause := connectionAbortCause(option.PolicyLease, route); cause != nil {
		err = cause
	} else if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		closeInBackground(conn)
		release()
		return nil, recordHTTPDialFailure(parent, option, err)
	}
	path, _ := option.trafficAttribution()
	stats.DefaultStore.RecordDial(path, time.Since(started))
	tracked := &mitmUpstreamConn{Conn: conn, httpUpstream: newHTTPUpstream(option, conn)}
	stop := watchAbort(nil, nil, route, func() { _ = tracked.Close() })
	return &dnsUpstreamConn{Conn: tracked, release: func() { stop(); release() }}, nil
}

func (c *ControlPlane) listenDNSUpstream(parent context.Context, option *DialOption, identity routingResult) (net.PacketConn, error) {
	ctx, cleanup, route, release, err := c.dnsDialLifetime(parent, option, identity)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	conn, _, err := dialHTTPPacketUpstream(ctx, option)
	if cause := connectionAbortCause(option.PolicyLease, route); cause != nil {
		err = cause
	}
	if err != nil {
		closeInBackground(conn)
		release()
		return nil, err
	}
	stop := watchAbort(nil, nil, route, func() { _ = conn.Close() })
	return &dnsUpstreamPacketConn{PacketConn: conn, release: func() { stop(); release() }}, nil
}

type dnsUpstreamConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *dnsUpstreamConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

type dnsUpstreamPacketConn struct {
	net.PacketConn
	once    sync.Once
	release func()
}

func (c *dnsUpstreamPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.release)
	return err
}
