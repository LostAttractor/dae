/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	// Value from OpenWRT default sysctl config
	DefaultNatTimeoutTCPEstablished = 7440 * time.Second
)

type tcpConnectionTracker struct {
	// mu serializes setup Add calls with the stopped transition before Wait.
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	setups      sync.WaitGroup
	stopped     bool
}

func (t *tcpConnectionTracker) beginSetup(conn net.Conn) bool {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		_ = conn.Close()
		return false
	}
	if t.connections == nil {
		t.connections = make(map[net.Conn]struct{})
	}
	t.connections[conn] = struct{}{}
	t.setups.Add(1)
	t.mu.Unlock()
	return true
}

func (t *tcpConnectionTracker) removeConnection(conn net.Conn) {
	t.mu.Lock()
	delete(t.connections, conn)
	t.mu.Unlock()
}

func (t *tcpConnectionTracker) stopAndSnapshot() []net.Conn {
	t.mu.Lock()
	t.stopped = true
	connections := make([]net.Conn, 0, len(t.connections))
	for conn := range t.connections {
		connections = append(connections, conn)
	}
	t.mu.Unlock()
	return connections
}

func (t *tcpConnectionTracker) stopAccepting() {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
}

func (t *tcpConnectionTracker) waitForSetups() {
	t.setups.Wait()
}

func (t *tcpConnectionTracker) finishSetup() {
	t.setups.Done()
}

func serveTCPConnection(c *ControlPlane, lConn net.Conn, ctx context.Context, tracker *tcpConnectionTracker) {
	defer tracker.removeConnection(lConn)
	relay, err := c.prepareTCPRelay(ctx, lConn)
	// Raw TCP relays retain only their dialer. MITM may route rewritten targets
	// until Host.Close drains its requests, before DNS and outbounds are closed.
	c = nil
	tracker.finishSetup()
	if relay != nil {
		err = relay.run()
	}
	if err != nil && ctx.Err() == nil {
		if log.IsLevelEnabled(log.DebugLevel) {
			fields := log.Fields{"source": lConn.RemoteAddr(), "destination": lConn.LocalAddr()}
			if relay != nil {
				fields["outbound"], fields["dialer"], fields["domain"] = relay.statsPath.Outbound, relay.statsPath.Dialer, relay.domain
			}
			log.WithFields(fields).WithError(err).Debug("TCP connection failed")
		}
	}
}

func (c *ControlPlane) prepareTCPRelay(setupCtx context.Context, lConn net.Conn) (relay *tcpRelay, err error) {
	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		_ = lConn.Close()
		return nil, fmt.Errorf("failed to retrieve target info %v: %w", dst.String(), err)
	}
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

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
	// Sniff target domain.
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
	if err != nil && !sniffing.IsSniffingError(err) {
		// We ignore lConn errors or temporary network errors
		if _, ok := IsNetError(err); ok {
			return nil, nil
		}
		return nil, fmt.Errorf("sniff TCP destination: %w", err)
	}

	host := domain
	if host == "" && sniffer.IsTLS() {
		host = dst.Addr().String()
	}

	// Route
	networkType := common.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	dialOption, mitmPlanner, release, err := c.prepareHTTPRoute(setupCtx, host, &RouteParam{
		routingResult: routingResult, networkType: networkType,
		Domain: domain, Src: src, Dest: dst,
	})
	if err != nil {
		return nil, err
	}
	if mitmPlanner != nil {
		var policyLease *netproxy.Lease
		if dialOption != nil {
			policyLease = dialOption.PolicyLease
		}
		return &tcpRelay{
			lConn: sniffer, src: src, dst: dst, domain: host,
			mitmHost: c.mitmHost, mitmPlanner: mitmPlanner, mitmRelease: release, routeLease: routeLease, policyLease: policyLease,
		}, nil
	}
	statsPath, noConnectivityFallback := dialOption.trafficAttribution()
	ctx, cancel := context.WithTimeout(setupCtx, consts.DefaultDialTimeout)
	defer cancel()
	stopPolicy := watchAbort(nil, dialOption.PolicyLease, nil, func() {
		cancel()
		setTCPResetOnClose(lConn)
		_ = lConn.Close()
	})
	defer stopPolicy()

	// Dial
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
		lConn:       sniffer,
		rConn:       rConn,
		dialer:      dialOption.Dialer,
		statsPath:   statsPath,
		fallback:    noConnectivityFallback,
		policyLease: dialOption.PolicyLease,
		routeLease:  routeLease,
		src:         src,
		dst:         dst,
		domain:      domain,
	}
	if dialOption.Direct {
		relay.outboundOrigin = netproxy.OriginTarget
	}
	if dialOption.Direct && dialOption.PolicyLease == nil && routeLease == nil && c.core.bpf.splice != nil {
		if _, ok := rConn.(splice.TCPConn); ok {
			relay.directSplice = c.core.bpf.splice
		}
	}
	return relay, nil
}
