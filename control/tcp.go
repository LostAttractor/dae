/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/prometheus/client_golang/prometheus"
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
	lConn        sniffing.ConnSnifferInterface
	rConn        net.Conn
	directSplice *directTCPSplice
	dialer       interface {
		ChecksConnectivity() bool
		ReportUnavailable()
	}
	labels       prometheus.Labels
	outboundName string
	dialerName   string
	src          netip.AddrPort
	dst          netip.AddrPort
	domain       string
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
	// Established relays must not retain the retired control plane across reloads.
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

	// Route
	networkType := &common.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	dialOption, err := c.RouteDialOption(setupCtx, &RouteParam{
		routingResult: routingResult,
		networkType:   networkType,
		Domain:        domain,
		Src:           src,
		Dest:          dst,
	})
	if err != nil {
		return nil, err
	}

	labels := prometheus.Labels{
		"id":       dialOption.Dialer.StatsID(),
		"outbound": dialOption.Outbound.Name,
		"subtag":   dialOption.Dialer.Property.SubscriptionTag,
		"dialer":   dialOption.Dialer.Name,
		"network":  networkType.String(),
	}

	// Dial
	LogDial(src, dst, domain, dialOption, networkType, routingResult)
	ctx, cancel := context.WithTimeout(setupCtx, consts.DefaultDialTimeout)
	defer cancel()
	start := time.Now()
	rConn, err := dialOption.dialerForConnection().DialContext(ctx, "tcp", dialOption.DialTarget)
	if err != nil {
		if ctxErr := setupCtx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// TODO: UDP 是不是也有Direct Outbound出问题的情况?
		// TODO: Control Plane Routing?
		// TODO: 哪些错误说明节点不工作或GFW在工作?
		// TCP: Connection Reset / Connection Refused
		netErr, ok := IsNetError(err)
		err = oops.
			In("DialContext").
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			With("Outbound", dialOption.Outbound.Name).
			With("Dialer", dialOption.Dialer.Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			Wrapf(err, "failed to DialContext")
		if !ok {
			return nil, err
		} else if !netErr.Timeout() {
			if dialOption.Dialer.ChecksConnectivity() {
				common.ErrorCount.With(labels).Inc()
				dialOption.Dialer.ReportUnavailable()
				return nil, err
			}
		}
		return nil, nil
	}
	if err := setupCtx.Err(); err != nil {
		closeInBackground(rConn)
		return nil, err
	}

	elapsed := time.Since(start).Seconds()
	common.DialLatency.With(labels).Observe(elapsed)
	relay = &tcpRelay{
		lConn:        sniffer,
		rConn:        rConn,
		dialer:       dialOption.Dialer,
		labels:       labels,
		outboundName: dialOption.Outbound.Name,
		dialerName:   dialOption.Dialer.Name,
		src:          src,
		dst:          dst,
		domain:       domain,
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
	defer r.rConn.Close()
	defer r.lConn.Close()
	labels := r.labels
	common.ActiveConnections.With(labels).Inc()
	defer common.ActiveConnections.With(labels).Dec()
	common.TotalConnections.With(labels).Inc()

	// Relay
	handled := false
	if r.directSplice != nil {
		err = r.lConn.WriteBufferedTo(r.rConn)
		if err == nil {
			handled, err = r.directSplice.runtime.Relay(
				r.directSplice.accepted, r.directSplice.remote)
		}
	}
	if !handled && err == nil {
		err = RelayTCP(r.lConn, r.rConn)
	}
	if err != nil {
		netErr, ok := IsNetError(err)
		err = oops.
			In("RelayTCP").
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			With("Outbound", r.outboundName).
			With("Dialer", r.dialerName).
			With("src", r.src.String()).
			With("dst", r.dst.String()).
			With("domain", r.domain).
			Wrapf(err, "Failed to RelayTCP")
		if !ok {
			return err
		} else if !netErr.Timeout() && r.dialer.ChecksConnectivity() {
			common.ErrorCount.With(labels).Inc()
			r.dialer.ReportUnavailable()
			return err
		}
	}
	// case strings.HasSuffix(err.Error(), "write: broken pipe"),
	// 	strings.HasSuffix(err.Error(), "i/o timeout"),
	// 	strings.HasPrefix(err.Error(), "EOF"),
	// 	strings.HasSuffix(err.Error(), "connection reset by peer"),
	// 	strings.HasSuffix(err.Error(), "canceled by local with error code 0"),
	// 	strings.HasSuffix(err.Error(), "canceled by remote with error code 0"):
	return nil
}

type ConnWithReadTimeout struct {
	net.Conn
}

func (c *ConnWithReadTimeout) Read(p []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(DefaultNatTimeoutTCPEstablished))
	return c.Conn.Read(p)
}

func relayDirection(dst, src net.Conn) (err error) {
	// As `io.Copy` uses a 32KB buffer, we create a buffer of the same size.
	// See https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/io/io.go;l=419
	bufPtr := pool.GetBuffer(1024 * 32) // 32KB
	defer pool.PutBuffer(bufPtr)

	_, err = io.CopyBuffer(dst, &ConnWithReadTimeout{Conn: src}, bufPtr)
	return
}

// Error1 is the error from lConn to rConn
// Error2 is the error from rConn to lConn
// TODO: 引入 ctx, 在 dialer 不可用时取消 relay
// 进一步的, 给 lConn 发送 rst
func RelayTCP(lConn, rConn net.Conn) error {
	errCh := make(chan struct {
		err       error
		direction bool
	}, 2)

	// Start relay goroutine from rConn to lConn
	go func(dst, src net.Conn) {
		err := relayDirection(dst, src)
		errCh <- struct {
			err       error
			direction bool
		}{err: err, direction: false}
		if err != nil {
			dst.Close()
		} else if writeCloser, ok := dst.(netproxy.CloseWriter); ok {
			writeCloser.CloseWrite()
		} else {
			dst.SetReadDeadline(time.Now().Add(10 * time.Second))
		}
	}(lConn, rConn)
	// Start relay goroutine from lConn to rConn
	func(dst, src net.Conn) {
		err := relayDirection(dst, src)
		errCh <- struct {
			err       error
			direction bool
		}{err: err, direction: true}
		if err != nil {
			dst.Close()
		} else if writeCloser, ok := dst.(netproxy.CloseWriter); ok {
			writeCloser.CloseWrite()
		} else {
			dst.SetReadDeadline(time.Now().Add(10 * time.Second))
		}
	}(rConn, lConn)
	err := <-errCh
	<-errCh

	if err.err != nil {
		// We ignore lConn errors or temporary network errors
		// TODO: Why get EOF as an error?
		if err.direction { // l -> r
			switch {
			case err.err == io.EOF,
				strings.HasSuffix(err.err.Error(), "canceled by remote with error code 0"), // rConn closed
				strings.Contains(err.err.Error(), "read:"):                                 // lConn Read
				err.err = nil
			default:
				err.err = oops.In("lConn -> rConn Relay").Wrap(err.err)
			}

		} else { // r -> l
			switch {
			case strings.Contains(err.err.Error(), "write:"): // lConn Write
				err.err = nil
			default:
				err.err = oops.In("rConn -> lConn Relay").Wrap(err.err)
			}
		}
	}

	return err.err
}
