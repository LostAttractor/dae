/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
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
	deadline, _ := ctx.Deadline()
	return writePacketUntil(ctx, deadline, nil, conn, data, dst)
}

// writePacketUntil bounds a write with the socket's own deadline and leaves no
// deadline behind. Cancellation reaches the write only through a worker slot,
// so a packet arms no timer or context. Only transports without deadline
// support need a timer, and transports that never block need neither.
func writePacketUntil(ctx context.Context, deadline time.Time, slot *udpWriteSlot, conn net.PacketConn, data []byte, dst net.Addr) (n int, err error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, context.DeadlineExceeded
	}
	if writer, ok := netproxy.PacketConnAs[netproxy.NonBlockingWriter](conn); ok {
		return writer.TryWriteTo(data, dst)
	}
	if !deadline.IsZero() {
		if conn.SetWriteDeadline(deadline) != nil {
			return writePacketWithTimer(ctx, deadline, conn, data, dst)
		}
		defer conn.SetWriteDeadline(time.Time{})
	}
	if err := slot.begin(ctx, conn); err != nil {
		return 0, err
	}
	n, err = conn.WriteTo(data, dst)
	slot.end()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		} else if errors.Is(err, os.ErrDeadlineExceeded) && !deadline.IsZero() && !time.Now().Before(deadline) {
			err = context.DeadlineExceeded
		}
	}
	return n, err
}

// The timer closes the socket: the transport offers no other way to stop a
// write at its deadline or on cancellation.
func writePacketWithTimer(ctx context.Context, deadline time.Time, conn net.PacketConn, data []byte, dst net.Addr) (n int, err error) {
	if inherited, exists := ctx.Deadline(); !exists || deadline.Before(inherited) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	interrupted := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		closeInBackground(conn)
		close(interrupted)
	})
	n, err = conn.WriteTo(data, dst)
	if !stopInterrupt() {
		<-interrupted
		err = ctx.Err()
	}
	return n, err
}

type udpPacketWork struct {
	plane         *ControlPlane
	src, dst      netip.AddrPort
	routingResult *routingResult
	deadline      time.Time
}

// A packet whose deadline passes before it is handled, or while its handling
// fails, is counted as expired; one its retired generation cancels is not.
func (w udpPacketWork) execute(slot *udpWriteSlot, data []byte) {
	c := w.plane
	ctx := c.udpTaskPool.ctx
	if c.ctx.Err() != nil || ctx.Err() != nil {
		return
	}
	if !time.Now().Before(w.deadline) {
		dropExpired.Add(1)
		return
	}
	err := c.handlePktUntil(ctx, w.deadline, slot, data, w.src, w.dst, w.routingResult)
	if err == nil || c.ctx.Err() != nil || ctx.Err() != nil {
		return
	}
	if !time.Now().Before(w.deadline) {
		dropExpired.Add(1)
		return
	}
	log.WithError(err).WithFields(log.Fields{"source": w.src, "destination": w.dst}).Debug("UDP packet handling failed")
}

// enqueueUDPPacket copies borrowed data into a pooled typed task. Deadlines
// include queue time; context timers are needed only for setup, MITM, new
// destination sockets and transports that cannot enforce socket deadlines.
func (c *ControlPlane) enqueueUDPPacket(data []byte, src, dst netip.AddrPort, routingResult *routingResult) {
	c.udpTaskPool.emit(data, udpPacketWork{
		plane: c, src: src, dst: dst, routingResult: routingResult,
		deadline: time.Now().Add(consts.DefaultDialTimeout),
	})
}

// handlePkt serializes the complete source lifetime, including sniffing and
// setup. An endpoint's first routing result never changes while it is in the pool.
func (c *ControlPlane) handlePkt(ctx context.Context, data []byte, src, dst netip.AddrPort, routingResult *routingResult) (err error) {
	deadline, _ := ctx.Deadline()
	return c.handlePktUntil(ctx, deadline, nil, data, src, dst, routingResult)
}

// ctx is the generation's work context; slot is the pool worker's write slot.
func (c *ControlPlane) handlePktUntil(ctx context.Context, deadline time.Time, slot *udpWriteSlot, data []byte, src, dst netip.AddrPort, routingResult *routingResult) (err error) {
	if dst.Port() == 53 && routingResult != nil && routingResult.Must == 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
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
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	ue, exists := p.Get(src)
	if !deadline.IsZero() && (!exists || ue.conn == nil || ue.mitm) {
		// Setup and MITM may wait on non-socket work.
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	if exists && ue.conn == nil {
		if owner := ue.setupOwner.Load(); owner != nil && owner != c {
			// A packet can queue before a predecessor publishes its endpoint.
			// Keep initialization (and the worker drain) in the owning generation.
			owner.enqueueUDPPacket(data, src, dst, nil)
			return nil
		}
	}
	if !exists || ue.conn == nil {
		if c.udpSetups.Add(1) > maxConcurrentUDPSetups {
			c.udpSetups.Add(-1)
			dropSetupCapacity.Add(1)
			return nil
		}
		defer c.udpSetups.Add(-1)
	}
	if !exists {
		// A queued packet may outlive the endpoint whose kernel binding sent
		// it here. Drop it; the next ingress packet will carry a fresh route.
		if routingResult == nil {
			dropRouteMissing.Add(1)
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
		replies := &udpReplySender{pool: DefaultAnyfromPool, to: src, mark: c.soMarkFromDae}
		ue = &UdpEndpoint{
			destinationSeed: maphash.MakeSeed(),
			generation:      c.routingGeneration,
			activity:        c.domainActivity(),
			routeLease:      routeLease,
			pending:         &udpSetup{routingResult: routingResult, sniffer: sniffing.NewPacketSniffer(nil)},
			firstDst:        dst,
			firstIfindex:    routingResult.Ifindex,
			NatTimeout:      udpSniffingTimeout,
			unbind:          unbind,
			replies:         replies,
		}
		ue.setupOwner.Store(c)
		if !p.addLocked(src, ue) {
			_ = ue.Close()
			dropEndpointLimit.Add(1)
			return nil
		}
		ue.stopWatching = append(ue.stopWatching, watchAbort(nil, nil, routeLease, func() {
			p.removeInBackground(src, ue)
		}))
	}
	if cause := ue.routeLease.AbortCause(); cause != nil {
		p.removeInBackgroundLocked(src, ue)
		return cause
	}
	if ue.conn != nil {
		ue.setupOwner.Store(nil)
		return c.writeUDPUntil(ctx, deadline, slot, ue, src, dst, data)
	}

	return c.initializeUDP(ctx, slot, ue, src, dst, data)
}

// initializeUDP runs under the source lock until the first route is installed.
// Later packets enter writeUDP directly, without routing or sniffing again.
func (c *ControlPlane) initializeUDP(ctx context.Context, slot *udpWriteSlot, ue *UdpEndpoint, src, dst netip.AddrPort, data []byte) (err error) {
	defer func() {
		if ue.conn != nil {
			ue.setupOwner.Store(nil)
		}
	}()
	p := c.udpEndpoints
	pending := ue.pending
	observedAt := time.Now()
	if ue.destinationSeed == (maphash.Seed{}) {
		ue.destinationSeed = maphash.MakeSeed()
	}

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
		domain, isQuic, err = pending.sniffer.SniffUdp()
		if err != nil && !sniffing.IsSniffingError(err) {
			pending.observedAt = time.Time{}
			ue.activity.observe(dst.Addr(), domain, observedAt)
			p.removeInBackgroundLocked(src, ue)
			return err
		}
		if pending.sniffer.NeedMore() {
			// Wait for the sniffed name, which selects the evidence the
			// activity renews.
			pending.observedAt = observedAt
			return nil
		}
	}

	ue.domain = domain
	network := common.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStrFromAddr(ue.firstDst.Addr())}
	param := &RouteParam{
		destinationSeed: &ue.destinationSeed,
		routingResult:   pending.routingResult, networkType: network,
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
	// A failed setup discards the packets buffered for sniffing and the
	// current one; execute does not see them.
	discard := func(drop *netproxy.Drop) {
		n := len(pending.sniffer.Data()) - 1 // Data()[0] is the empty seed
		if dst != ue.firstDst {
			n++
		}
		drop.Add(uint64(n))
	}
	expired := func() bool {
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false
		}
		discard(dropExpired)
		return true
	}
	// Activity renews the destination's DNS evidence; failed attempts count.
	pending.observedAt = time.Time{}
	ue.activity.observe(ue.firstDst.Addr(), domain, observedAt)
	if dst != ue.firstDst {
		ue.activity.observe(dst.Addr(), "", observedAt)
	}
	if err != nil {
		p.removeInBackgroundLocked(src, ue)
		// A blocked flow has no association to preserve. A later packet can
		// try again after the group recovers.
		if _, blocked := errors.AsType[*routeBlocked](err); blocked || expired() {
			return nil
		}
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
		conn, err = p.packetBudget().Open(ctx, "", func(context.Context, string) (net.PacketConn, error) {
			return c.newMITMQUIC(param, planner, release, ue.routeLease), nil
		})
		if err != nil {
			if release != nil {
				release()
			}
			p.removeInBackgroundLocked(src, ue)
			if errors.Is(err, netproxy.ErrPacketCapacity) {
				discard(dropResourceLimit)
				return nil
			}
			return err
		}
	} else {
		path, fallback := option.trafficAttribution()
		ue.policyLease = option.PolicyLease
		ue.fallback = fallback
		ue.dialer, ue.statsPath = option.Dialer, path
		if option.Direct {
			ue.origin = netproxy.OriginTarget
		}
		label := network.String()
		if isQuic {
			label = "quic" + string(network.IpVersion)
		}
		c.logDial(src, ue.firstDst, domain, option, label, pending.routingResult)

		upstream := newUpstreamDial(option)
		upstream.route = ue.routeLease
		conn, err = upstream.establishUpstream(ctx, func(ctx context.Context) (net.PacketConn, error) {
			return p.packetBudget().Open(ctx, option.DialTarget, option.dialerForConnection().ListenPacket)
		})
		if err != nil {
			p.removeInBackgroundLocked(src, ue)
			if cause := connectionAbortCause(option.PolicyLease, ue.routeLease); cause != nil {
				return cause
			}
			if errors.Is(err, netproxy.ErrPacketCapacity) {
				discard(dropResourceLimit) // establishUpstream recorded the error
				return nil
			}
			if expired() || !recordDataPlaneError(ue.dialer, path, err) {
				return nil
			}
			return fmt.Errorf("open UDP association via outbound %q node %q: %w", path.Outbound, ue.dialer.Name, err)
		}
	}
	var socketKey netip.AddrPort
	if option != nil && (ue.mitm || c.routingMatcher != nil && len(c.routingMatcher.destinationProgram(param.routingResult.ProfileId).predicates) != 0) {
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
		ue.destinations = map[netip.AddrPort]udpDestination{ue.firstDst: {target, time.Now()}}
		ue.sockets = make(map[netip.AddrPort]*udpSocket)
		if ue.mitm {
			socketKey = ue.firstDst
		} else if target != ue.firstDst {
			socketKey = ue.firstDst
			conn = newDestinationPacketConn(conn, ue.firstDst, target)
		}
	}

	ue.conn = conn
	ue.lease = netproxy.NewLease(netproxy.ResourceRef{})
	if !ue.mitm {
		ue.traffic = stats.DefaultStore.OpenDeviceConnection(ue.statsPath, ue.fallback, pending.routingResult.Mac)
	}
	ue.NatTimeout = DefaultNatTimeoutUDP
	p.refreshTimerLocked(src, ue, time.Now())
	ue.startSocket(p, src, ue.firstDst, socketKey, conn)

	// Send the buffered first destination in arrival order, followed by the
	// packet that completed initialization (if it uses another destination).
	sniffer := pending.sniffer
	ue.pending = nil
	defer sniffer.Close()
	deadline, _ := ctx.Deadline()
	for _, packet := range sniffer.Data()[1:] {
		if err := c.writeUDPUntil(ctx, deadline, slot, ue, src, ue.firstDst, packet); err != nil || ue.IsClosed() {
			return err
		}
	}
	if dst != ue.firstDst {
		if err := c.writeUDPUntil(ctx, deadline, slot, ue, src, dst, data); err != nil || ue.IsClosed() {
			return err
		}
	}

	return nil
}

func (c *ControlPlane) writeUDP(ctx context.Context, ue *UdpEndpoint, src, dst netip.AddrPort, data []byte) error {
	deadline, _ := ctx.Deadline()
	return c.writeUDPUntil(ctx, deadline, nil, ue, src, dst, data)
}

func (c *ControlPlane) writeUDPUntil(ctx context.Context, deadline time.Time, slot *udpWriteSlot, ue *UdpEndpoint, src, dst netip.AddrPort, data []byte) error {
	ue.observeDomain(dst)
	// Request-routing HTTP/3 has no connection-wide outbound. Its source
	// lifetime is scoped to the admitted destination; it cannot migrate.
	if ue.mitm && ue.packetDialer == nil && dst != ue.firstDst {
		dropUploadFiltered.Add(1)
		return nil
	}
	if cause := connectionAbortCause(ue.lease, ue.policyLease, ue.routeLease); cause != nil {
		c.udpEndpoints.removeInBackgroundLocked(src, ue)
		return cause
	}
	// The deadline includes the packet's queue time and bounds any new socket.
	conn, err := ue.socket(ctx, deadline, c.udpEndpoints, src, dst)
	var n int
	if err == nil {
		// Writes are serialized by the source key lock. Cache the common
		// destination without retaining an unbounded per-source address map.
		if ue.writeAddr == nil || ue.writeDst != dst {
			ue.writeDst, ue.writeAddr = dst, net.UDPAddrFromAddrPort(dst)
		}
		n, err = writePacketUntil(ctx, deadline, slot, conn, data, ue.writeAddr)
		if err == netproxy.ErrPacketDropped {
			// Counted by the transport; not uploaded, not a failure.
			return nil
		}
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
	if errors.Is(err, netproxy.ErrPacketCapacity) {
		// Counted here; execute could count a returned error as expired.
		recordDataPlaneError(ue.dialer, ue.statsPath, err)
		dropResourceLimit.Add(1)
		return nil
	}
	if ue.mitm && conn == ue.conn || !recordDataPlaneError(ue.dialer, ue.statsPath, err) {
		if errors.Is(err, context.DeadlineExceeded) {
			dropExpired.Add(1) // A returned error would be counted by execute.
		}
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
