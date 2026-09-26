/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	// Values from OpenWRT default sysctl config
	DefaultNatTimeoutUDP = 60 * time.Second
)

const (
	// Reserve workers for established associations; setup admission never waits.
	maxConcurrentUDPSetups = udpTaskMaxWorkers / 4
	// Tunnels and large-MTU interfaces can deliver reassembled datagrams
	// larger than an Ethernet frame. Never forward a truncated payload.
	udpReceiveBufferSize = 65535
	udpSniffingTimeout   = 3 * time.Second
	DnsNatTimeout        = 17 * time.Second // RFC 5452
	MaxRetry             = 2
)

func shouldTryRawUDPFallback(err error, from, to netip.AddrPort) bool {
	if err == nil || !from.IsValid() || !to.IsValid() || from.Port() != 53 {
		return false
	}
	from4 := from.Addr().Is4() || from.Addr().Is4In6()
	to4 := to.Addr().Is4() || to.Addr().Is4In6()
	if from4 != to4 {
		return false
	}
	if errors.Is(err, unix.EADDRINUSE) || errors.Is(err, unix.EADDRNOTAVAIL) {
		return true
	}
	errString := strings.ToLower(err.Error())
	return strings.Contains(errString, "address already in use") ||
		strings.Contains(errString, "cannot assign requested address")
}

func tryRawUDPFallback(data []byte, from, to netip.AddrPort, mark uint32, reason string, trigger error) bool {
	if !shouldTryRawUDPFallback(trigger, from, to) {
		return false
	}
	var err error
	if from.Addr().Is4() || from.Addr().Is4In6() {
		err = sendUDPv4RawInDaeNetns(data, from, to, mark)
	} else {
		err = sendUDPv6RawInDaeNetns(data, from, to, mark)
	}
	if err == nil {
		log.WithFields(log.Fields{"source": from, "destination": to, "operation": reason}).Trace("Sent DNS response through raw UDP fallback")
		return true
	}
	log.WithFields(log.Fields{
		"source": from, "destination": to, "operation": reason,
		"socket_error": trigger,
	}).WithError(err).Debug("Raw UDP fallback failed")
	return false
}

// sendPkt uses a transparent UDP socket first and falls back to a raw DNS
// response when the source address cannot be bound.
func sendPktWithMark(data []byte, from, to netip.AddrPort, mark uint32) (err error) {
	uConn, _, err := DefaultAnyfromPool.GetOrCreate(from, DefaultAnyfromCacheTTL)
	if err != nil {
		if tryRawUDPFallback(data, from, to, mark, "get-or-create", err) {
			return nil
		}
		return
	}
	_, err = uConn.WriteToUDPAddrPortWithDeadline(data, to, time.Now().Add(consts.DefaultDNSTimeout))
	if err != nil && tryRawUDPFallback(data, from, to, mark, "write-to-udp", err) {
		return nil
	}
	return err
}

func writePacket(ctx context.Context, conn net.PacketConn, data []byte, dst net.Addr) (n int, err error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	deadlineSet := false
	if deadline, ok := ctx.Deadline(); ok {
		deadlineSet = conn.SetWriteDeadline(deadline) == nil
	}
	interrupted := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		_ = conn.SetWriteDeadline(time.Now())
		if !deadlineSet || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			closeInBackground(conn)
		}
		close(interrupted)
	})
	n, err = conn.WriteTo(data, dst)
	if !stopInterrupt() {
		<-interrupted
		err = ctx.Err()
	}
	if deadlineSet {
		_ = conn.SetWriteDeadline(time.Time{})
	}
	return n, err
}

// enqueueUDPPacket borrows data only until emit returns. Queued packets retain
// an absolute deadline, but allocate their context/timer only when dispatched.
func (c *ControlPlane) enqueueUDPPacket(data []byte, src, dst netip.AddrPort, routingResult *bpfRoutingResult) {
	deadline := time.Now().Add(consts.DefaultDialTimeout)
	c.udpTaskPool.emit(src, data, func(owned []byte) udpTask {
		return func() {
			if c.ctx.Err() != nil || c.udpTaskPool.ctx.Err() != nil || !time.Now().Before(deadline) {
				return
			}
			ctx, cancel := context.WithDeadline(c.udpTaskPool.ctx, deadline)
			defer cancel()
			if err := c.handlePkt(ctx, owned, src, dst, routingResult); err != nil && ctx.Err() == nil {
				log.WithError(err).WithFields(log.Fields{"source": src, "destination": dst}).Debug("UDP packet handling failed")
			}
		}
	})
}

// handlePkt serializes the complete source lifetime, including sniffing and
// setup. An endpoint's first routing result never changes while it is in the pool.
func (c *ControlPlane) handlePkt(ctx context.Context, data []byte, src, dst netip.AddrPort, routingResult *bpfRoutingResult) (err error) {
	if dst.Port() == 53 && routingResult != nil && routingResult.Must == 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.handleDNSUDP(data, src, dst, *routingResult)
		c.domainActivity().observe(dst.Addr(), "", time.Now())
		return nil
	}
	p := c.udpEndpoints
	lock, _ := p.UdpEndpointKeyLocker.Lock(src)
	defer p.UdpEndpointKeyLocker.Unlock(src, lock)
	if err := ctx.Err(); err != nil {
		return err
	}
	ue, exists := p.Get(src)
	if !exists || ue.conn == nil {
		if c.udpSetups.Add(1) > maxConcurrentUDPSetups {
			c.udpSetups.Add(-1)
			c.udpSetupDrops.report("setup capacity")
			return nil
		}
		defer c.udpSetups.Add(-1)
	}
	if !exists {
		// A queued packet may outlive the endpoint whose kernel binding sent
		// it here. Drop it; the next ingress packet will carry a fresh route.
		if routingResult == nil {
			return nil
		}
		routeLease, err := c.deviceRoutes.acquire(routingResult)
		if err != nil {
			return err
		}
		unbind, err := c.bindUDPSource(src, routingResult)
		if err != nil {
			return err
		}
		mark := c.soMarkFromDae
		ue = &UdpEndpoint{
			activity:     c.domainActivity(),
			routeLease:   routeLease,
			pending:      &udpSetup{routingResult: routingResult, sniffer: sniffing.NewPacketSniffer(nil)},
			firstDst:     dst,
			firstIfindex: routingResult.Ifindex,
			NatTimeout:   udpSniffingTimeout,
			unbind:       unbind,
			handler: func(data []byte, from netip.AddrPort) error {
				return sendPktWithMark(data, from, src, mark)
			},
		}
		p.addLocked(src, ue)
		ue.stopWatching = append(ue.stopWatching, watchAbort(nil, nil, routeLease, func() {
			p.removeInBackground(src, ue)
		}))
	}
	if cause := ue.routeLease.AbortCause(); cause != nil {
		p.removeInBackgroundLocked(src, ue)
		return cause
	}
	if ue.conn != nil {
		return c.writeUDP(ctx, ue, src, dst, data)
	}

	return c.initializeUDP(ctx, ue, src, dst, data)
}

// initializeUDP runs under the source lock until the first route is installed.
// Later packets enter writeUDP directly, without routing or sniffing again.
func (c *ControlPlane) initializeUDP(ctx context.Context, ue *UdpEndpoint, src, dst netip.AddrPort, data []byte) (err error) {
	p := c.udpEndpoints
	pending := ue.pending
	observedAt := time.Now()

	ctx, cancelRoute := context.WithCancel(ctx)
	defer cancelRoute()
	stopRoute := watchAbort(nil, nil, ue.routeLease, cancelRoute)
	defer stopRoute()

	// Only the first destination participates in sniffing. A different
	// destination completes initialization with the information already known.
	var domain string
	var isQuic bool
	if dst == ue.firstDst {
		pending.sniffer.AppendData(data)
		if pending.routingResult.NoSniff == 0 {
			domain, isQuic, err = pending.sniffer.SniffUdp()
		}
		if err != nil && !sniffing.IsSniffingError(err) {
			pending.observedAt = time.Time{}
			ue.activity.observe(dst.Addr(), domain, observedAt)
			p.removeInBackgroundLocked(src, ue)
			return err
		}
		if pending.sniffer.NeedMore() {
			// Wait for the sniff identity before refreshing. Publishing an IP
			// promotion here could hide the first packet's kernel coverage gap
			// from the eventual routing decision.
			pending.observedAt = observedAt
			return nil
		}
	}

	ue.domain = domain
	network := common.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStrFromAddr(ue.firstDst.Addr())}
	param := &RouteParam{
		routingResult: pending.routingResult, networkType: network,
		Domain: domain, Src: src, Dest: ue.firstDst,
	}
	var option *DialOption
	var planner mitm.UpstreamPlanner
	var release func()
	if pending.sniffer.IsHTTP3() {
		if param.Domain == "" {
			param.Domain = ue.firstDst.Addr().String()
		}
		option, planner, release, err = c.prepareHTTPRoute(ctx, param.Domain, param)
	} else {
		option, err = c.RouteDialOption(ctx, param)
	}
	// Preserve the initial kernel-coverage decision before activity can promote
	// an omitted candidate. The client's attempt counts even if routing fails.
	pending.observedAt = time.Time{}
	ue.activity.observe(ue.firstDst.Addr(), domain, observedAt)
	if dst != ue.firstDst {
		ue.activity.observe(dst.Addr(), "", observedAt)
	}
	if err != nil {
		p.removeInBackgroundLocked(src, ue)
		return err
	}
	var conn net.PacketConn
	ue.mitm = planner != nil
	if ue.mitm {
		if option != nil {
			ue.dialer = option.Dialer
			ue.statsPath, ue.fallback = option.trafficAttribution()
			ue.policyLease = option.PolicyLease
			if option.Direct {
				ue.origin = netproxy.OriginTarget
			}
		}
		conn = c.newMITMQUIC(param, planner, release, ue.routeLease)
	} else {
		// A block fallback has no association to preserve. A later packet can
		// try again after the group recovers.
		if option.Outbound.Name == consts.OutboundBlock.String() {
			p.removeInBackgroundLocked(src, ue)
			return nil
		}
		path, fallback := option.trafficAttribution()
		ue.policyLease = option.PolicyLease
		ue.traffic = stats.DefaultStore.OpenConnection(path, fallback)
		ue.dialer, ue.statsPath = option.Dialer, path
		if option.Direct {
			ue.origin = netproxy.OriginTarget
		}
		label := network.String()
		if isQuic {
			label = "quic" + string(network.IpVersion)
		}
		c.logDial(src, ue.firstDst, domain, option, label, pending.routingResult)

		dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		stopSetup := watchAbort(nil, option.PolicyLease, nil, cancel)
		var dialErr error
		conn, dialErr = option.dialerForConnection().ListenPacket(dialCtx, option.DialTarget)
		setupErr := dialCtx.Err()
		stopSetup()
		cancel()
		if cause := connectionAbortCause(option.PolicyLease, ue.routeLease); cause != nil {
			closeInBackground(conn)
			p.removeInBackgroundLocked(src, ue)
			return cause
		}
		if dialErr != nil {
			p.removeInBackgroundLocked(src, ue)
			err = netproxy.WrapFailure(dialErr, netproxy.Failure{Phase: netproxy.OpDial, Origin: ue.origin})
			if !recordDataPlaneError(ue.dialer, path, err) {
				return nil
			}
			return fmt.Errorf("open UDP association via outbound %q node %q: %w", path.Outbound, ue.dialer.Name, err)
		}
		if setupErr != nil {
			closeInBackground(conn)
			p.removeInBackgroundLocked(src, ue)
			return setupErr
		}
	}
	var socketKey netip.AddrPort
	if option != nil && (ue.mitm || c.routingMatcher != nil && len(c.routingMatcher.destination.predicates) != 0) {
		ue.releaseDialer, err = option.Dialer.Retain()
		if err != nil {
			closeInBackground(conn)
			p.removeInBackgroundLocked(src, ue)
			return err
		}
		ue.packetDialer = option.dialerForConnection()
		if c.routingMatcher != nil {
			ue.destinationMatcher = c.routingMatcher.snapshotDestinations()
		}
		ue.destinationParam = *param
		target := param.effectiveDestination()
		ue.destinations = map[netip.AddrPort]netip.AddrPort{ue.firstDst: target}
		ue.sockets = make(map[netip.AddrPort]net.PacketConn)
		if ue.mitm {
			socketKey = ue.firstDst
		} else if target != ue.firstDst {
			socketKey = ue.firstDst
			conn = &destinationPacketConn{PacketConn: conn, original: ue.firstDst, target: target}
		}
	}

	ue.conn = conn
	ue.lease = netproxy.DependencyOf(conn)
	ue.NatTimeout = DefaultNatTimeoutUDP
	p.refreshTimerLocked(src, ue, time.Now())
	ue.startSocket(p, src, ue.firstDst, socketKey, conn)

	// Send the buffered first destination in arrival order, followed by the
	// packet that completed initialization (if it uses another destination).
	sniffer := pending.sniffer
	ue.pending = nil
	defer sniffer.Close()
	for _, packet := range sniffer.Data()[1:] {
		if err := c.writeUDP(ctx, ue, src, ue.firstDst, packet); err != nil || ue.IsClosed() {
			return err
		}
	}
	if dst != ue.firstDst {
		if err := c.writeUDP(ctx, ue, src, dst, data); err != nil || ue.IsClosed() {
			return err
		}
	}

	return nil
}

func (c *ControlPlane) writeUDP(ctx context.Context, ue *UdpEndpoint, src, dst netip.AddrPort, data []byte) error {
	ue.observeDomain(dst)
	// Request-routing HTTP/3 has no connection-wide outbound. Its source
	// lifetime is scoped to the admitted destination; it cannot migrate.
	if ue.mitm && ue.packetDialer == nil && dst != ue.firstDst {
		return nil
	}
	if cause := connectionAbortCause(ue.lease, ue.policyLease, ue.routeLease); cause != nil {
		c.udpEndpoints.removeInBackgroundLocked(src, ue)
		return cause
	}
	// The dispatch context already includes the packet's queue time in its deadline.
	conn, err := ue.socket(ctx, c.udpEndpoints, src, dst)
	var n int
	if err == nil {
		n, err = writePacket(ctx, conn, data, net.UDPAddrFromAddrPort(dst))
	}
	if !(ue.mitm && conn == ue.conn) && n > 0 && ue.traffic != nil {
		ue.traffic.RecordUpload(uint64(n))
	}
	if err == nil {
		return nil
	}
	if cause := connectionAbortCause(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease); cause != nil {
		err = cause
	} else if ue.mitm && conn == ue.conn && plainClosedError(err) {
		c.udpEndpoints.removeInBackgroundLocked(src, ue)
		return nil
	} else {
		err = netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpWrite, Origin: ue.origin})
	}
	if !temporaryUDPError(err) || connectionAbortCause(ue.lease, ue.policyLease, ue.routeLease) != nil {
		c.udpEndpoints.removeInBackgroundLocked(src, ue)
	}
	if ue.mitm && conn == ue.conn || !recordDataPlaneError(ue.dialer, ue.statsPath, err) {
		return nil
	}
	return fmt.Errorf("send UDP packet via outbound %q node %q: %w", ue.statsPath.Outbound, ue.dialer.Name, err)
}

// Datagram/target errors do not invalidate an association shared by other
// destinations. A shared-resource failure is always handled by its owner.
func temporaryUDPError(err error) bool {
	if err == nil {
		return false
	}
	for _, failure := range netproxy.Failures(err) {
		if failure.Scope == netproxy.ScopeSharedResource || failure.Scope == netproxy.ScopeStream {
			return false
		}
		if failure.Scope == netproxy.ScopeOperation && failure.Reason == netproxy.ReasonCapacity {
			continue
		}
		if timeout, ok := errors.AsType[net.Error](failure.Cause); ok && timeout.Timeout() {
			continue
		}
		if failure.Layer != netproxy.LayerUnknown && failure.Layer != "" && failure.Layer != netproxy.LayerUDP {
			return false
		}
		if errors.Is(failure.Cause, unix.EMSGSIZE) || errors.Is(failure.Cause, unix.ENOBUFS) {
			continue
		}
		if failure.Origin != netproxy.OriginTarget || !(errors.Is(failure.Cause, unix.ECONNREFUSED) ||
			errors.Is(failure.Cause, unix.ENETUNREACH) || errors.Is(failure.Cause, unix.EHOSTUNREACH)) {
			return false
		}
	}
	return true
}
