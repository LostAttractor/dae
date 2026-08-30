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
	"github.com/daeuniverse/dae/component/sniffing"
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

func (c *ControlPlane) handlePkt(ctx context.Context, data []byte, src, dst netip.AddrPort, skipSniffing bool, domain string, isQuic bool) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	udpEndpoints := c.udpEndpoints

	/// Sniff
	if !skipSniffing {
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
			domain, isQuic, err = sniffer.SniffUdp()
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
				if replayErr := c.handlePkt(ctx, d, src, dst, true, domain, isQuic); replayErr != nil {
					log.Warnf("%+v", oops.Wrapf(replayErr, "rehandlePkt"))
				}
			}
		} else {
			_sniffer.Mu.Unlock()
			// sniffer may be nil.
		}
	}

	/// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.

	l, _ := udpEndpoints.UdpEndpointKeyLocker.Lock(src)
	defer udpEndpoints.UdpEndpointKeyLocker.Unlock(src, l)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Get udp endpoint.
	ue, ok := udpEndpoints.Get(src)
	isNew := false
	networkType := &common.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	// If the udp endpoint has been not alive, remove it from pool and retry
	// UDP 不是面向连接的, 在 tcp 中, 一个连接失败, 我们会重置中继它, 等待一个新的连接
	// 在 UDP 中, l -> r继续中继到新的节点, 并在新的节点上进行 r -> l 中继
	if ok && !ue.dialer.Usable(networkType) {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"src":     RefineSourceToShow(src, dst.Addr()),
				"network": networkType.String(),
				"dialer":  ue.dialer.Name,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		udpEndpoints.removeInBackgroundLocked(src, ue)
		ok = false
	}
	if !ok {
		routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_UDP)
		if err != nil {
			return oops.Wrapf(err, "RetrieveRoutingResult")
		}
		// Route
		dialOption, err := c.RouteDialOption(ctx, &RouteParam{
			routingResult: routingResult,
			networkType:   networkType,
			Domain:        domain,
			Src:           src,
			Dest:          dst,
		})
		if err != nil {
			return err
		}

		// Do not overwrite target.
		// This fixes a problem that quic connection to google servers.
		// Reproduce:
		// docker run --rm --name curl-http3 ymuski/curl-http3 curl --http3 -o /dev/null -v -L https://i.ytimg.com
		dialOption.DialTarget = dst.String()

		statsPath := dialOption.Dialer.StatsPath(dialOption.Outbound.Name, networkType)

		// Dial
		// Only print routing for new connection to avoid the log exploded (Quic and BT).
		network := networkType.String()
		if isQuic {
			network = "quic" + string(networkType.IpVersion)
		}
		c.logDial(src, dst, domain, dialOption, network, routingResult)
		dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		defer cancel()
		udpConn, err := dialOption.dialerForConnection().ListenPacket(dialCtx, dialOption.DialTarget)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			netErr, ok := IsNetError(err)
			err = oops.
				In("ListenPacket").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", domain).
				Wrapf(err, "failed to ListenPacket")
			if !ok {
				return err
			} else if !netErr.Timeout() {
				if dialOption.Dialer.ChecksConnectivity() {
					stats.DefaultStore.RecordError(statsPath)
					dialOption.Dialer.ReportDataPlaneFailure()
					return err
				}
			}
			return nil
		}
		soMark := c.soMarkFromDae
		ue = newUdpEndpoint(&UdpEndpointOptions{
			PacketConn: udpConn,
			Handler: func(data []byte, from netip.AddrPort) (err error) {
				return sendPktWithMark(data, from, src, soMark)
			},
			NatTimeout: DefaultNatTimeoutUDP,
			Dialer:     dialOption.Dialer,
			Path:       statsPath,
		})
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
			udpEndpoints.removeInBackgroundLocked(src, ue)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		netErr, ok := IsNetError(err)
		err = oops.
			In("UdpEndpoint l -> r relay").
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			With("Dialer", ue.dialer.Name).
			Wrapf(err, "failed to write UDP packet")
		if !ok {
			return err
		} else if !netErr.Timeout() {
			if ue.dialer.ChecksConnectivity() {
				stats.DefaultStore.RecordError(ue.statsPath)
				ue.dialer.ReportDataPlaneFailure()
				return err
			}
		}
		return nil
	}
	if isNew {
		ue.traffic = stats.DefaultStore.OpenConnection(ue.statsPath)
	}
	if n > 0 {
		ue.traffic.RecordUpload(uint64(n))
	}
	if !isNew {
		return nil
	}

	// The first write is the setup-to-endpoint handoff. Only publish the
	// endpoint after the write completed before cancellation.
	udpEndpoints.addLocked(src, ue)
	go func(endpointPool *UdpEndpointPool, endpoint *UdpEndpoint) {
		runErr := endpoint.run(endpointPool, src, dst)
		endpointPool.remove(src, endpoint)
		if runErr == nil {
			return
		}
		netErr, ok := IsNetError(runErr)
		if ok {
			if netErr.Timeout() {
				return
			}
			if endpoint.dialer.ChecksConnectivity() {
				stats.DefaultStore.RecordError(endpoint.statsPath)
				endpoint.dialer.ReportDataPlaneFailure()
			}
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Warnf("%+v", runErr)
		} else {
			oopsErr, _ := oops.AsOops(runErr)
			log.WithFields(log.Fields(oopsErr.Context())).Warnf("%v", runErr)
		}
	}(udpEndpoints, ue)

	return nil
}
