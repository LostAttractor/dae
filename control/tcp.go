/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	// Value from OpenWRT default sysctl config
	DefaultNatTimeoutTCPEstablished = 7440 * time.Second
)

type directTCPSplice struct {
	runtime  *splice.Runtime
	accepted splice.TCPConn
	remote   splice.TCPConn
}

type tcpRelay struct {
	lConn          sniffing.ConnSnifferInterface
	rConn          net.Conn
	directSplice   *directTCPSplice
	dialer         *dialer.Dialer
	outboundOrigin netproxy.FailureOrigin
	statsPath      stats.Path
	fallback       bool
	src            netip.AddrPort
	dst            netip.AddrPort
	domain         string
	mitmHost       *mitm.Host
	mitmPlanner    mitm.UpstreamPlanner
	mitmRelease    func()
}

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
			log.Warnf("%+v", oops.Wrapf(err, "handleConn"))
		} else {
			log.Warnf("%v", oops.Wrapf(err, "handleConn"))
		}
	}
}

func (c *ControlPlane) prepareTCPRelay(setupCtx context.Context, lConn net.Conn) (relay *tcpRelay, err error) {
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
		return nil, oops.Wrapf(err, "Sniff Failed")
	}

	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to retrieve target info %v", dst.String())
	}
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)
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
		return &tcpRelay{
			lConn: sniffer, src: src, dst: dst, domain: host,
			mitmHost: c.mitmHost, mitmPlanner: mitmPlanner, mitmRelease: release,
		}, nil
	}
	statsPath, noConnectivityFallback := dialOption.trafficAttribution()

	// Dial
	c.logDial(src, dst, domain, dialOption, dialOption.NetworkType.String(), routingResult)
	ctx, cancel := context.WithTimeout(setupCtx, consts.DefaultDialTimeout)
	defer cancel()
	start := time.Now()
	rConn, err := dialOption.dialerForConnection().DialContext(ctx, "tcp", dialOption.DialTarget)
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
		return nil, oops.In("DialContext").
			With("Outbound", dialOption.Outbound.Name).
			With("Dialer", dialOption.Dialer.Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			Wrapf(err, "failed to DialContext")
	}
	if err := setupCtx.Err(); err != nil {
		closeInBackground(rConn)
		return nil, err
	}

	stats.DefaultStore.RecordDial(statsPath, time.Since(start))
	relay = &tcpRelay{
		lConn:     sniffer,
		rConn:     rConn,
		dialer:    dialOption.Dialer,
		statsPath: statsPath,
		fallback:  noConnectivityFallback,
		src:       src,
		dst:       dst,
		domain:    domain,
	}
	if dialOption.Direct {
		relay.outboundOrigin = netproxy.OriginTarget
	}
	if dialOption.Direct && c.core.bpf.splice != nil {
		if rawRConn, ok := rConn.(splice.TCPConn); ok {
			relay.directSplice = &directTCPSplice{
				c.core.bpf.splice, lConn.(*net.TCPConn), rawRConn,
			}
		}
	}
	return relay, nil
}

func (r *tcpRelay) run() (err error) {
	if r.mitmRelease != nil {
		defer r.mitmRelease()
	}
	if r.rConn != nil {
		defer r.rConn.Close()
	}
	defer r.lConn.Close()
	if r.mitmHost != nil {
		return r.mitmHost.ServeConn(r.lConn, r.domain, r.dst.Port(), r.mitmPlanner)
	}
	traffic := stats.DefaultStore.OpenConnection(r.statsPath, r.fallback)
	defer func() { err = errors.Join(err, traffic.Close()) }()

	// Relay
	handled := false
	if r.directSplice != nil {
		accepted := &relayEndpoint{conn: r.directSplice.accepted, origin: netproxy.OriginCaller}
		remote := &relayEndpoint{conn: r.directSplice.remote, origin: netproxy.OriginTarget}
		err = r.lConn.WriteBufferedTo(&trafficWriter{Writer: remote, add: traffic.RecordUpload})
		if err == nil {
			handled, err = r.directSplice.runtime.Relay(
				&spliceEndpoint{TCPConn: r.directSplice.accepted, endpoint: accepted},
				&spliceEndpoint{TCPConn: r.directSplice.remote, endpoint: remote}, traffic)
		}
	}
	if !handled && err == nil {
		err = relayTCP(r.lConn, r.rConn, traffic, 10*time.Second, r.outboundOrigin)
	} else {
		err = withoutCleanupErrors(err)
	}
	if recordDataPlaneError(r.dialer, r.statsPath, err) {
		return oops.In("RelayTCP").
			With("Outbound", r.statsPath.Outbound).
			With("Dialer", r.statsPath.Dialer).
			With("src", r.src.String()).
			With("dst", r.dst.String()).
			With("domain", r.domain).
			Wrapf(err, "failed to relay TCP")
	}
	return nil
}

type trafficWriter struct {
	io.Writer
	add func(uint64)
}

func (w *trafficWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.add(uint64(n))
	}
	return n, err
}

func relayEndpointDirection(dst, src *relayEndpoint, add func(uint64)) error {
	return copyRelay(&trafficWriter{Writer: dst, add: add}, src)
}

func relayTCP(lConn, rConn net.Conn, traffic *stats.Connection, drainTimeout time.Duration, origin netproxy.FailureOrigin) error {
	type result struct {
		err        error
		needsDrain bool
	}
	results := make(chan result, 2)
	left := &relayEndpoint{conn: lConn, origin: netproxy.OriginCaller}
	right := &relayEndpoint{conn: rConn, origin: origin}
	lease := netproxy.DependencyOf(rConn)
	invalidated := lease.Done()
	copyDirection := func(dst, src *relayEndpoint, add func(uint64)) {
		outcome := result{err: relayEndpointDirection(dst, src, add)}
		// copyRelay consumes read EOF. Propagate FIN only while the owner
		// still allows it; resource cleanup can itself surface as EOF.
		if outcome.err == nil && lease.AbortCause() == nil {
			outcome.needsDrain, outcome.err = dst.halfClose()
		}
		// Keep CloseWrite in the worker: an owner abort must be able to
		// interrupt it if sending FIN blocks.
		results <- outcome
	}
	go copyDirection(left, right, traffic.RecordDownload)
	go copyDirection(right, left, traffic.RecordUpload)

	var timer *time.Timer
	var timeout <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	aborted := false
	var relayErr error
	abort := func() {
		if aborted {
			return
		}
		aborted = true
		timeout = nil
		invalidated = nil
		// Check the owner signal even if a copy result won the select race.
		if cause := lease.AbortCause(); cause != nil {
			relayErr = errors.Join(relayErr, cause)
			setTCPResetOnClose(lConn)
		}
		// Unblock both reads and writes, including a reverse copy blocked
		// writing to the endpoint whose read side has already ended.
		_ = left.close()
		_ = right.close()
	}
	for remaining := 2; remaining > 0; {
		select {
		case <-invalidated:
			invalidated = nil
			if lease.AbortCause() != nil {
				abort()
			}
		case outcome := <-results:
			remaining--
			relayErr = errors.Join(relayErr, outcome.err)
			if outcome.err != nil || lease.AbortCause() != nil {
				abort()
			} else if outcome.needsDrain && remaining == 1 && !aborted {
				// A connection without CloseWrite cannot propagate EOF. Give
				// the reverse copy a fixed grace period after the first EOF.
				timer = time.NewTimer(drainTimeout)
				timeout = timer.C
			}
		case <-timeout:
			relayErr = errors.Join(relayErr, netproxy.WrapFailure(context.DeadlineExceeded, netproxy.Failure{Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonDeadline}))
			abort()
		}
	}
	return withoutCleanupErrors(relayErr)
}
