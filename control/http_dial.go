// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

func logHTTPDial(source netip.AddrPort, domain string, option *DialOption, err error) {
	entry := log.WithFields(log.Fields{
		"event": "upstream_dial", "domain": domain, "destination": option.DialTarget,
		"outbound": option.Outbound.Name, "dialer": option.Dialer.Name, "mark": option.Mark,
	})
	if source.IsValid() {
		entry = entry.WithField("source", source.String())
	}
	if option.OriginalOutbound != nil {
		entry = entry.WithField("original_outbound", option.OriginalOutbound.Name)
	}
	if policy := option.Outbound.DisplayPolicy(); policy != "" {
		entry = entry.WithField("policy", policy)
	}
	if err != nil {
		entry.WithError(resource.RedactError(err)).Debug("MITM upstream dial failed")
	} else if !source.IsValid() {
		entry.Debug("MITM client connected")
	} else {
		entry.Info("MITM upstream connected")
	}
}

// Attribute HTTP traffic to its actual upstream route. A client connection may
// visit several outbounds, and local responses must not open a fictitious route.
func dialHTTPUpstream(parent context.Context, option *DialOption) (net.Conn, error) {
	if option.Outbound.Name == consts.OutboundBlock.String() {
		return nil, fmt.Errorf("HTTP upstream blocked by routing")
	}
	conn, err := newUpstreamDial(option).establishUpstream(parent, func(ctx context.Context) (net.Conn, error) {
		return option.dialerForConnection().DialContext(ctx, "tcp", option.DialTarget)
	})
	if err != nil {
		return nil, err
	}
	return &mitmUpstreamConn{Conn: conn, httpUpstream: newHTTPUpstream(option, conn)}, nil
}

type mitmUpstreamConn struct {
	net.Conn
	*httpUpstream
}

func (c *mitmUpstreamConn) CloseWrite() error {
	err := netproxy.CloseWrite(c.Conn)
	if err == errors.ErrUnsupported {
		return err
	}
	return c.failure(err, netproxy.OpWrite)
}

func (c *mitmUpstreamConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.traffic.RecordDownload(uint64(n))
	if err == io.EOF {
		return n, err
	}
	return n, c.failure(err, netproxy.OpRead)
}

func (c *mitmUpstreamConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.traffic.RecordUpload(uint64(n))
	return n, c.failure(err, netproxy.OpWrite)
}

func (c *mitmUpstreamConn) Close() error {
	c.retire()
	return c.Conn.Close()
}

func dialHTTPPacketUpstream(parent context.Context, option *DialOption) (net.PacketConn, net.Addr, error) {
	conn, err := newUpstreamDial(option).establishUpstream(parent, func(ctx context.Context) (net.PacketConn, error) {
		return option.dialerForConnection().ListenPacket(ctx, option.DialTarget)
	})
	if err != nil {
		return nil, nil, err
	}
	return &mitmUpstreamPacketConn{PacketConn: conn, httpUpstream: newHTTPUpstream(option, conn)}, netproxy.NewAddr("udp", option.DialTarget), nil
}

type mitmUpstreamPacketConn struct {
	net.PacketConn
	*httpUpstream
}

func (c *mitmUpstreamPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(data)
	c.traffic.RecordDownload(uint64(n))
	return n, from, c.failure(err, netproxy.OpRead)
}

func (c *mitmUpstreamPacketConn) WriteTo(data []byte, to net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(data, to)
	c.traffic.RecordUpload(uint64(n))
	return n, c.failure(err, netproxy.OpWrite)
}

func (c *mitmUpstreamPacketConn) Close() error {
	c.retire()
	return c.PacketConn.Close()
}

// Both HTTP transports account at the selected upstream and expose its actual
// resource and group-policy lifetime to the accepted TCP/QUIC connection.
type httpUpstream struct {
	traffic  *stats.Connection
	dialer   *dialer.Dialer
	path     stats.Path
	origin   netproxy.FailureOrigin
	lease    *netproxy.Lease
	resource *netproxy.Lease
	policy   *netproxy.Lease
	stop     func()
	closed   atomic.Bool
}

func newHTTPUpstream(option *DialOption, conn io.Closer) *httpUpstream {
	path, fallback := option.trafficAttribution()
	u := &httpUpstream{traffic: stats.DefaultStore.OpenDeviceConnection(path, fallback, option.DeviceMAC), dialer: option.Dialer, path: path,
		lease: netproxy.NewLease(netproxy.NewResourceRef()), resource: netproxy.DependencyOf(conn), policy: option.PolicyLease}
	if option.Direct {
		u.origin = netproxy.OriginTarget
	}
	u.stop = watchAbort(u.resource, u.policy, nil, func() {
		u.lease.Abort(connectionAbortCause(u.resource, u.policy))
		_ = u.traffic.Close()
		closeInBackground(conn)
	})
	return u
}

func (u *httpUpstream) DependencyLease() *netproxy.Lease { return u.lease }
func (u *httpUpstream) retire() {
	if u.closed.Swap(true) {
		return
	}
	u.stop()
	// Transport cleanup can outrun the watcher after a failed Read. Preserve
	// the owner's already-published abort before fixing this lease's outcome.
	if cause := connectionAbortCause(u.resource, u.policy); cause != nil {
		u.lease.Abort(cause)
	} else {
		u.lease.Invalidate(net.ErrClosed)
	}
	_ = u.traffic.Close()
}
func (u *httpUpstream) failure(err error, phase netproxy.Operation) error {
	if err == nil || u.closed.Load() && plainClosedError(err) {
		return err
	}
	if cause := u.lease.AbortCause(); cause != nil {
		err = cause
	} else {
		err = netproxy.WrapFailure(err, netproxy.Failure{Phase: phase, Origin: u.origin})
	}
	recordDataPlaneError(u.dialer, u.path, err)
	return err
}
