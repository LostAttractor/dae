// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// DNS transports share the data plane's accounting and resource/policy leases.
// The plugin owns the connection and must close it before its invocation ends.
func (c *ControlPlane) retainDNSUpstream(option *DialOption, identity routingResult) (*netproxy.Lease, func(), error) {
	route, err := c.deviceRoutes.acquire(&identity)
	if err != nil {
		return nil, nil, err
	}
	release, err := option.Dialer.Retain()
	if err != nil {
		return nil, nil, err
	}
	return route, release, nil
}

func (c *ControlPlane) dialDNSUpstream(parent context.Context, network string, option *DialOption, identity routingResult) (net.Conn, error) {
	route, release, err := c.retainDNSUpstream(option, identity)
	if err != nil {
		return nil, err
	}
	upstream := newUpstreamDial(option)
	upstream.route = route
	conn, err := upstream.establishUpstream(parent, func(ctx context.Context) (net.Conn, error) {
		return option.dialerForConnection().DialContext(ctx, network, option.DialTarget)
	})
	if err != nil {
		release()
		return nil, err
	}
	tracked := &mitmUpstreamConn{Conn: conn, httpUpstream: newHTTPUpstream(option, conn)}
	stop := watchAbort(nil, nil, route, func() { _ = tracked.Close() })
	return &dnsUpstreamConn{Conn: tracked, release: func() { stop(); release() }}, nil
}

func (c *ControlPlane) listenDNSUpstream(parent context.Context, option *DialOption, identity routingResult) (net.PacketConn, error) {
	route, release, err := c.retainDNSUpstream(option, identity)
	if err != nil {
		return nil, err
	}
	upstream := newUpstreamDial(option)
	upstream.route = route
	conn, err := upstream.establishUpstream(parent, func(ctx context.Context) (net.PacketConn, error) {
		return option.dialerForConnection().ListenPacket(ctx, option.DialTarget)
	})
	if err != nil {
		release()
		return nil, err
	}
	tracked := &mitmUpstreamPacketConn{PacketConn: conn, httpUpstream: newHTTPUpstream(option, conn)}
	stop := watchAbort(nil, nil, route, func() { _ = tracked.Close() })
	return &dnsUpstreamPacketConn{PacketConn: tracked, release: func() { stop(); release() }}, nil
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
