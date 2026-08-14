/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"

	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/prometheus/client_golang/prometheus"
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

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
func sendPkt(data []byte, from, to netip.AddrPort) (err error) {
	uConn, _, err := DefaultAnyfromPool.GetOrCreate(from, DefaultAnyfromCacheTTL)
	if err != nil {
		return
	}
	_, err = uConn.WriteToUDPAddrPortWithDeadline(data, to, time.Now().Add(consts.DefaultDNSTimeout))
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

func (c *ControlPlane) handlePkt(ctx context.Context, data []byte, src, dst netip.AddrPort, skipSniffing bool) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	udpEndpoints := c.udpEndpoints
	var domain string

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
			domain, err = sniffer.SniffUdp()
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
			defer DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
			// Re-handlePkt after self func.
			toRehandle := sniffer.Data()[1 : len(sniffer.Data())-1] // Skip the first empty and the last (self).
			sniffer.Mu.Unlock()
			if len(toRehandle) > 0 {
				defer func() {
					if err == nil {
						for _, d := range toRehandle {
							err := c.handlePkt(ctx, d, src, dst, true)
							if err != nil {
								log.Warnf("%+v", oops.Wrapf(err, "rehandlePkt"))
							}
						}
					}
				}()
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
	// If the udp endpoint has been not alive, remove it from pool and retry
	// UDP 不是面向连接的, 在 tcp 中, 一个连接失败, 我们会重置中继它, 等待一个新的连接
	// 在 UDP 中, l -> r继续中继到新的节点, 并在新的节点上进行 r -> l 中继
	if ok && !ue.dialer.Alive() {
		if log.IsLevelEnabled(log.DebugLevel) {
			networkType := &common.NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
			}
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
		networkType := &common.NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
		}
		// Use an empty AddrPort for dst
		routingResult, err := c.core.RetrieveRoutingResult(src, netip.AddrPort{}, unix.IPPROTO_UDP)
		if err != nil {
			return oops.Wrapf(err, "No AddrPort presented")
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

		labels := prometheus.Labels{
			"id":       dialOption.Dialer.StatsID(),
			"outbound": dialOption.Outbound.Name,
			"subtag":   dialOption.Dialer.Property.SubscriptionTag,
			"dialer":   dialOption.Dialer.Name,
			"network":  networkType.String(),
		}

		// Dial
		// Only print routing for new connection to avoid the log exploded (Quic and BT).
		LogDial(src, dst, domain, dialOption, networkType, routingResult)
		dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		defer cancel()
		udpConn, err := dialOption.Dialer.ListenPacket(dialCtx, dialOption.DialTarget)
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
				if dialOption.Dialer.NeedAliveState() {
					common.ErrorCount.With(labels).Inc()
					dialOption.Dialer.ReportUnavailable()
					return err
				}
			}
			return nil
		}
		ue = newUdpEndpoint(&UdpEndpointOptions{
			PacketConn: udpConn,
			Handler: func(data []byte, from netip.AddrPort) (err error) {
				return sendPkt(data, from, src)
			},
			NatTimeout: DefaultNatTimeoutUDP,
			Dialer:     dialOption.Dialer,
			labels:     labels,
		})
		isNew = true
	}

	// TODO: What is realSrc/Dst?
	// Try to write data
	writeCtx, cancelWrite := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer cancelWrite()
	_, err = writePacket(writeCtx, ue.conn, data, net.UDPAddrFromAddrPort(dst))
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
			if ue.dialer.NeedAliveState() {
				common.ErrorCount.With(ue.labels).Inc()
				ue.dialer.ReportUnavailable()
				return err
			}
		}
		return nil
	}
	if !isNew {
		return nil
	}

	// The first write is the setup-to-endpoint handoff. Only publish the
	// endpoint after the write completed before cancellation.
	udpEndpoints.addLocked(src, ue)
	go func(endpointPool *UdpEndpointPool, endpoint *UdpEndpoint) {
		runErr := endpoint.run(endpointPool, src)
		endpointPool.remove(src, endpoint)
		if runErr == nil {
			return
		}
		netErr, ok := IsNetError(runErr)
		if ok {
			if netErr.Timeout() {
				return
			}
			if endpoint.dialer.NeedAliveState() {
				common.ErrorCount.With(endpoint.labels).Inc()
				endpoint.dialer.ReportUnavailable()
			}
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Warnf("%+v", runErr)
		} else {
			log.Warnf("%v", runErr)
		}
	}(udpEndpoints, ue)

	return nil
}
