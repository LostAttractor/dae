// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
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
		entry.WithError(err).Debug("mitm")
	} else {
		entry.Info("mitm")
	}
}

// Attribute HTTP traffic to its actual upstream route. A client connection may
// visit several outbounds, and local responses must not open a fictitious route.
func (c *ControlPlane) dialHTTPUpstream(parent context.Context, option *DialOption) (net.Conn, error) {
	if option.Outbound.Name == consts.OutboundBlock.String() {
		return nil, fmt.Errorf("HTTP upstream blocked by routing")
	}
	ctx, cancel := context.WithTimeout(parent, consts.DefaultDialTimeout)
	defer cancel()
	path, fallback := option.trafficAttribution()
	started := time.Now()
	conn, err := option.dialerForConnection().DialContext(ctx, "tcp", option.DialTarget)
	if err != nil {
		stats.DefaultStore.RecordError(path)
		if parent.Err() == nil && option.Dialer.ChecksConnectivity() {
			if netErr, ok := IsNetError(err); ok && !netErr.Timeout() {
				option.Dialer.ReportDataPlaneFailure()
			}
		}
		return nil, err
	}
	stats.DefaultStore.RecordDial(path, time.Since(started))
	traffic := stats.DefaultStore.OpenConnection(path, fallback)
	return &mitmUpstreamConn{Conn: conn, traffic: traffic}, nil
}

type mitmUpstreamConn struct {
	net.Conn
	traffic   *stats.Connection
	closeOnce sync.Once
}

func (c *mitmUpstreamConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.traffic.RecordDownload(uint64(n))
	return n, err
}

func (c *mitmUpstreamConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.traffic.RecordUpload(uint64(n))
	return n, err
}

func (c *mitmUpstreamConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { _ = c.traffic.Close() })
	return err
}

func (c *ControlPlane) dialHTTPPacketUpstream(parent context.Context, option *DialOption) (net.PacketConn, net.Addr, error) {
	ctx, cancel := context.WithTimeout(parent, consts.DefaultDialTimeout)
	defer cancel()
	path, fallback := option.trafficAttribution()
	started := time.Now()
	conn, err := option.dialerForConnection().ListenPacket(ctx, option.DialTarget)
	if err != nil {
		stats.DefaultStore.RecordError(path)
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		closeInBackground(conn)
		return nil, nil, err
	}
	stats.DefaultStore.RecordDial(path, time.Since(started))
	return &mitmUpstreamPacketConn{PacketConn: conn, traffic: stats.DefaultStore.OpenConnection(path, fallback)}, netproxy.NewAddr("udp", option.DialTarget), nil
}

type mitmUpstreamPacketConn struct {
	net.PacketConn
	traffic   *stats.Connection
	closeOnce sync.Once
}

func (c *mitmUpstreamPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(data)
	c.traffic.RecordDownload(uint64(n))
	return n, from, err
}

func (c *mitmUpstreamPacketConn) WriteTo(data []byte, to net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(data, to)
	c.traffic.RecordUpload(uint64(n))
	return n, err
}

func (c *mitmUpstreamPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.closeOnce.Do(func() { _ = c.traffic.Close() })
	return err
}
