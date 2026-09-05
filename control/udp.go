/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
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
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	// Values from OpenWRT default sysctl config
	DefaultNatTimeoutUDP = 60 * time.Second
)

const (
	DnsNatTimeout = 17 * time.Second // RFC 5452
	MaxRetry      = 2
	// Leave worker capacity for established associations while new routes or
	// proxy handshakes are slow. Admission never waits inside a packet worker.
	maxConcurrentUDPSetups = udpTaskMaxWorkers / 4
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
		log.WithFields(log.Fields{"from": from, "to": to, "reason": reason}).Debug("sendPkt: used raw UDP fallback")
		return true
	}
	log.WithFields(log.Fields{
		"from": from, "to": to, "reason": reason,
		"trigger": trigger, "fallback": err,
	}).Error("sendPkt: raw UDP fallback failed")
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
	stopInterrupt := context.AfterFunc(ctx, func() {
		_ = conn.SetWriteDeadline(time.Now())
		closeInBackground(conn)
	})
	n, err = conn.WriteTo(data, dst)
	if !stopInterrupt() {
		return n, ctx.Err()
	}
	if deadlineSet {
		_ = conn.SetWriteDeadline(time.Time{})
	}
	return n, err
}

// enqueueUDPPacket borrows data only until emit returns. Queued packets retain
// an absolute deadline, but allocate their context/timer only when dispatched.
func (c *ControlPlane) enqueueUDPPacket(data []byte, src, dst netip.AddrPort) {
	deadline := time.Now().Add(consts.DefaultDialTimeout)
	c.udpTaskPool.emit(src, data, func(owned []byte) udpTask {
		return func() {
			if c.ctx.Err() != nil || !time.Now().Before(deadline) {
				return
			}
			ctx, cancel := context.WithDeadline(c.ctx, deadline)
			defer cancel()
			if err := c.handlePkt(ctx, owned, src, dst, nil); err != nil && ctx.Err() == nil {
				if log.IsLevelEnabled(log.DebugLevel) {
					log.Warnf("%+v", oops.Wrapf(err, "handlePkt"))
				} else {
					log.Warnf("%v", oops.Wrapf(err, "handlePkt"))
				}
			}
		}
	})
}

type packetSniff struct {
	domain      string
	quic, http3 bool
}

func (c *ControlPlane) handlePkt(ctx context.Context, data []byte, src, dst netip.AddrPort, sniffed *packetSniff) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	udpEndpoints := c.udpEndpoints

	/// Sniff
	if sniffed == nil {
		sniffed = new(packetSniff)
		// Sniff Quic, ...
		key := PacketSnifferKey{
			LAddr: src,
			RAddr: dst,
		}
		_sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
		_sniffer.Mu.Lock()
		// Re-get sniffer from pool to confirm the transaction is not done.
		sniffer := DefaultPacketSnifferSessionMgr.Get(key)
		if _sniffer == sniffer {
			sniffer.AppendData(data)
			sniffed.domain, sniffed.quic, err = sniffer.SniffUdp()
			sniffed.http3 = sniffer.IsHTTP3()
			if err != nil && !sniffing.IsSniffingError(err) {
				sniffer.Mu.Unlock()
				return oops.
					With("from", src).
					With("to", dst).
					Wrapf(err, "sniffUDP non sniffing error")
			}
			if sniffer.NeedMore() {
				sniffer.Mu.Unlock()
				return nil
			}
			if err != nil && log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%+v", oops.
					With("from", src).
					With("to", dst).
					Wrapf(err, "sniffUDP"))
			}
			// Replay earlier datagrams with the completed sniff result before the
			// triggering packet so routing is correct without reordering the flow.
			toRehandle := sniffer.Data()[1 : len(sniffer.Data())-1] // Skip the first empty and the last (self).
			if removeErr := DefaultPacketSnifferSessionMgr.removeLocked(key, sniffer); removeErr != nil {
				log.Warnf("remove packet sniffer: %v", removeErr)
			}
			sniffer.Mu.Unlock()
			for _, d := range toRehandle {
				if replayErr := c.handlePkt(ctx, d, src, dst, sniffed); replayErr != nil {
					log.Warnf("%+v", oops.Wrapf(replayErr, "rehandlePkt"))
				}
			}
		} else {
			_sniffer.Mu.Unlock()
			// sniffer may be nil.
		}
	}

	domain, isQuic := sniffed.domain, sniffed.quic

	/// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.

	routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_UDP)
	if err != nil {
		return oops.Wrapf(err, "RetrieveRoutingResult")
	}
	mitmHost := domain
	if mitmHost == "" {
		mitmHost = dst.Addr().String()
	}
	key := c.mitmUDPEndpointKey(src, dst, routingResult, sniffed)
	l, _ := udpEndpoints.UdpEndpointKeyLocker.Lock(key)
	defer udpEndpoints.UdpEndpointKeyLocker.Unlock(key, l)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Get udp endpoint.
	ue, ok := udpEndpoints.Get(key)
	var previousDestination netip.AddrPort
	networkType := common.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	if ok && key.Destination.IsValid() {
		previousDestination = ue.destination
		domain = ue.domain
		networkType.IpVersion = ue.statsPath.Network.NetworkType().IpVersion
	}
	isNew := false
	noConnectivityFallback := false
	// If the udp endpoint has been not alive, remove it from pool and retry
	// UDP 不是面向连接的, 在 tcp 中, 一个连接失败, 我们会重置中继它, 等待一个新的连接
	// 在 UDP 中, l -> r继续中继到新的节点, 并在新的节点上进行 r -> l 中继
	if ok && !ue.mitm && !ue.dialer.Usable(&networkType) {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"src":     RefineSourceToShow(src, dst.Addr()),
				"network": networkType.String(),
				"dialer":  ue.dialer.Name,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		udpEndpoints.removeInBackgroundLocked(key, ue)
		ok = false
	}
	if !ok {
		if c.udpSetups.Add(1) > maxConcurrentUDPSetups {
			c.udpSetups.Add(-1)
			c.udpSetupDrops.report("association_setup_limit")
			return nil
		}
		defer c.udpSetups.Add(-1)
		// Route
		param := &RouteParam{
			destination:   previousDestination,
			routingResult: routingResult,
			networkType:   networkType,
			Domain:        domain,
			Src:           src,
			Dest:          dst,
		}
		var dialOption *DialOption
		var planner mitm.UpstreamPlanner
		var release func()
		if sniffed.http3 {
			param.Domain = mitmHost
			dialOption, planner, release, err = c.prepareHTTPRoute(ctx, mitmHost, param)
		} else {
			dialOption, err = c.RouteDialOption(ctx, param)
		}
		if err != nil {
			return err
		}

		intercept := planner != nil
		var statsPath stats.Path
		var udpConn net.PacketConn
		if intercept {
			udpConn = c.newMITMQUIC(param, planner, release)
		} else {
			statsPath, noConnectivityFallback = dialOption.trafficAttribution()
			if dst.Port() == 53 && routingResult.Must == 0 && routingResult.CaptureFlags&captureDestination != 0 && dialOption.Outbound.Name != "block" && !param.destination.IsValid() {
				var message dnsmessage.Msg
				if err := message.Unpack(data); err == nil {
					c.dnsController.Handle(&message, &udpRequest{src: src, dst: dst, routingResult: routingResult})
					return nil
				}
			}

			// Dial
			// Only print routing for new connection to avoid the log exploded (Quic and BT).
			network := dialOption.NetworkType.String()
			if isQuic {
				network = "quic" + string(dialOption.NetworkType.IpVersion)
			}
			c.logDial(src, dst, domain, dialOption, network, routingResult)
			dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
			defer cancel()
			udpConn, err = dialOption.dialerForConnection().ListenPacket(dialCtx, dialOption.DialTarget)
			if err != nil {
				meta := netproxy.Failure{Phase: netproxy.OpDial}
				if dialOption.Direct {
					meta.Origin = netproxy.OriginTarget
				}
				err = netproxy.WrapFailure(err, meta)
				if !recordDataPlaneError(dialOption.Dialer, statsPath, err) {
					return nil
				}
				return oops.Wrapf(err, "failed to ListenPacket")
			}
		}
		if key.Destination.IsValid() {
			if !intercept {
				if target := param.effectiveDestination(); target != dst {
					udpConn = &destinationPacketConn{PacketConn: udpConn, original: dst, target: target}
				}
			}
			if routingResult.CaptureFlags&(captureDestination|captureHTTP) != 0 || intercept {
				ownedResult := *routingResult
				if intercept {
					// Retain this proven association, including an explicit bump
					// without a DNS mapping. This adds no capture rule for new flows.
					ownedResult.CaptureFlags |= captureHTTP
				}
				owned, err := c.ownDestinationUDP(udpConn, key, &ownedResult)
				if err != nil {
					_ = udpConn.Close()
					return oops.Wrapf(err, "retain UDP destination ownership")
				}
				udpConn = owned
			}
		}
		soMark := c.soMarkFromDae
		ue = newUdpEndpoint(&UdpEndpointOptions{
			PacketConn: udpConn,
			Handler: func(data []byte, from netip.AddrPort) (err error) {
				return sendPktWithMark(data, from, src, soMark)
			},
			NatTimeout: DefaultNatTimeoutUDP,
			Path:       statsPath,
		})
		ue.mitm = intercept
		if !intercept {
			ue.dialer = dialOption.Dialer
			ue.destination = param.effectiveDestination()
		}
		ue.domain = domain
		if dialOption.Direct {
			ue.origin = netproxy.OriginTarget
		}
		isNew = true
	}

	// TODO: What is realSrc/Dst?
	// Try to write data
	writeCtx, cancelWrite := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer cancelWrite()
	n, err := writePacket(writeCtx, ue.conn, data, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		if isNew {
			closeInBackground(ue)
		} else {
			udpEndpoints.removeInBackgroundLocked(key, ue)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if ue.mitm {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		err = netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpWrite, Origin: ue.origin})
		if !recordDataPlaneError(ue.dialer, ue.statsPath, err) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return nil
		}
		return oops.In("UdpEndpoint l -> r relay").With("Dialer", ue.dialer.Name).
			Wrapf(err, "failed to write UDP packet")
	}
	if isNew && !ue.mitm {
		ue.traffic = stats.DefaultStore.OpenConnection(ue.statsPath, noConnectivityFallback)
	}
	if n > 0 && ue.traffic != nil {
		ue.traffic.RecordUpload(uint64(n))
	}
	if !isNew {
		return nil
	}

	// The first write is the setup-to-endpoint handoff. Only publish the
	// endpoint after the write completed before cancellation.
	udpEndpoints.addLocked(key, ue)
	go func(endpointPool *UdpEndpointPool, endpoint *UdpEndpoint) {
		runErr := endpoint.run(endpointPool, key, dst)
		endpointPool.remove(key, endpoint)
		if runErr == nil {
			return
		}
		if !recordDataPlaneError(endpoint.dialer, endpoint.statsPath, runErr) {
			return
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Warnf("%+v", runErr)
		} else {
			log.Warnf("%v", runErr)
		}
	}(udpEndpoints, ue)

	return nil
}
