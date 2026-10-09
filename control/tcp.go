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
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
)

const (
	// Value from OpenWRT default sysctl config
	DefaultNatTimeoutTCPEstablished = 7440 * time.Second
)

// prepareTCPRelay owns connection setup through sniffing, routing, and dialing.
// A non-nil result transfers connection ownership to tcpRelay.run.
func (c *ControlPlane) prepareTCPRelay(setupCtx context.Context, lConn net.Conn, routingResult *routingResult) (relay *tcpRelay, err error) {
	// Runtime has consumed the handoff and selected its owning generation.
	src, dst := lConn.RemoteAddr().(*net.TCPAddr).AddrPort(), lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)
	if dst.Port() == 53 && routingResult.Must == 0 {
		c.domainActivity().observe(dst.Addr(), "", time.Now())
		observe := c.domainActivity().connection(dst.Addr(), "")
		lConn = &activityConn{lConn, observe}
		return &tcpRelay{
			lConn: sniffing.NewConnSniffer(lConn, 0), dst: dst,
			custom: func() error { return c.serveDNSTCP(lConn, src, dst, *routingResult) },
		}, nil
	}

	routeLease, err := c.deviceRoutes.acquire(routingResult)
	if err != nil {
		setTCPResetOnClose(lConn)
		_ = lConn.Close()
		return nil, err
	}
	setupCtx, cancelSetup := context.WithCancel(setupCtx)
	defer cancelSetup()
	stopRoute := watchAbort(nil, nil, routeLease, func() {
		setTCPResetOnClose(lConn)
		cancelSetup()
		_ = lConn.Close()
	})
	defer stopRoute()

	// Cancellation owns the accepted connection until setup hands it to the relay.
	sniffer := sniffing.NewConnSniffer(lConn, c.sniffingTimeout)
	stopClose := context.AfterFunc(setupCtx, func() { _ = lConn.Close() })
	defer func() {
		if relay == nil {
			stopClose()
			_ = sniffer.Close()
		} else if !stopClose() {
			_ = sniffer.Close()
			closeInBackground(relay.rConn)
			if relay.mitmRelease != nil {
				relay.mitmRelease()
			}
			relay = nil
			err = setupCtx.Err()
		}
	}()

	domain, err := sniffer.SniffTcp()
	observedAt := time.Now()
	if err != nil && !sniffing.IsSniffingError(err) {
		c.domainActivity().observe(dst.Addr(), domain, observedAt)
		// We ignore lConn errors or temporary network errors
		if _, ok := errors.AsType[net.Error](err); ok {
			return nil, nil
		}
		return nil, fmt.Errorf("sniff TCP destination: %w", err)
	}
	observe := c.domainActivity().connection(dst.Addr(), domain)
	sniffer = &activitySniffer{sniffer, observe}

	host := domain
	if host == "" && sniffer.IsTLS() {
		host = dst.Addr().String()
	}

	// Select the route and any MITM plan using the sniffed identity.
	networkType := common.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	dialOption, mitmPlanner, release, err := c.prepareHTTPRoute(setupCtx, host, &RouteParam{
		routingResult: routingResult, networkType: networkType,
		Domain: domain, Src: src, Dest: dst,
	})
	// Route against the pre-activity projection first. Promoting a missing IP
	// before verification would conceal the kernel coverage gap that requires
	// while_needed rerouting for this connection. Failed attempts still count.
	c.domainActivity().observe(dst.Addr(), domain, observedAt)
	if err != nil {
		return nil, err
	}
	if mitmPlanner != nil {
		var policyLease *netproxy.Lease
		if dialOption != nil {
			policyLease = dialOption.PolicyLease
		}
		return &tcpRelay{
			lConn: sniffer, dst: dst, domain: host,
			activity:    observe,
			mitmHost:    c.MITMHost(),
			mitmPlanner: mitmPlanner,
			mitmRelease: release,
			routeLease:  routeLease,
			policyLease: policyLease,
		}, nil
	}

	// Ordinary relays establish their outbound before leaving the setup phase.
	statsPath, noConnectivityFallback := dialOption.trafficAttribution()
	ctx, cancel := context.WithTimeout(setupCtx, consts.DefaultDialTimeout)
	defer cancel()
	stopPolicy := watchAbort(nil, dialOption.PolicyLease, nil, func() {
		cancel()
		setTCPResetOnClose(lConn)
		_ = lConn.Close()
	})
	defer stopPolicy()

	c.logDial(src, dst, domain, dialOption, dialOption.NetworkType.String(), routingResult)
	start := time.Now()
	rConn, err := dialOption.dialerForConnection().DialContext(ctx, "tcp", dialOption.DialTarget)
	if cause := connectionAbortCause(dialOption.PolicyLease, routeLease); cause != nil {
		setTCPResetOnClose(lConn)
		closeInBackground(rConn)
		return nil, cause
	}
	if err != nil {
		meta := netproxy.Failure{Phase: netproxy.OpDial}
		if dialOption.Direct {
			meta.Origin = netproxy.OriginTarget
		}
		err = netproxy.WrapFailure(err, meta)
		if !recordDataPlaneError(dialOption.Dialer, statsPath, err) {
			if ctxErr := setupCtx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, nil
		}
		return nil, fmt.Errorf("connect TCP outbound %q via %q for %q: %w", dialOption.Outbound.Name, dialOption.Dialer.Name, domain, err)
	}
	if err := setupCtx.Err(); err != nil {
		closeInBackground(rConn)
		return nil, err
	}

	stats.DefaultStore.RecordDial(statsPath, time.Since(start))
	relay = &tcpRelay{
		activity:    observe,
		lConn:       sniffer,
		rConn:       rConn,
		dialer:      dialOption.Dialer,
		statsPath:   statsPath,
		fallback:    noConnectivityFallback,
		policyLease: dialOption.PolicyLease,
		routeLease:  routeLease,
		dst:         dst,
		domain:      domain,
	}
	if dialOption.Direct {
		relay.outboundOrigin = netproxy.OriginTarget
	}
	// Splice only accelerates an already-captured direct connection. Connections
	// governed by policy or route leases need the userspace abort watcher.
	if dialOption.Direct && dialOption.PolicyLease == nil && routeLease == nil && c.core.bpf.Runtime != nil && c.core.bpf.splice != nil {
		if _, ok := rConn.(splice.TCPConn); ok {
			relay.directSplice = c.core.bpf.splice
		}
	}
	return relay, nil
}
