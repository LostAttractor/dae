package control

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
)

type tcpRelay struct {
	lConn  sniffing.ConnSnifferInterface
	rConn  net.Conn
	dst    netip.AddrPort
	domain string

	// Ordinary relay dependencies and accounting.
	directSplice   *splice.Runtime
	dialer         *dialer.Dialer
	outboundOrigin netproxy.FailureOrigin
	statsPath      stats.Path
	deviceMAC      [6]byte
	fallback       bool
	routeLease     *netproxy.Lease
	policyLease    *netproxy.Lease
	activity       func()

	// DNS and MITM take over the accepted connection instead of copying bytes.
	custom      func() error
	mitmHost    *mitm.Host
	mitmPlanner mitm.UpstreamPlanner
	mitmRelease func()
}

func (r *tcpRelay) run() (err error) {
	if r.mitmRelease != nil {
		defer r.mitmRelease()
	}
	if r.rConn != nil {
		defer r.rConn.Close()
	}
	defer r.lConn.Close()
	if r.custom != nil {
		return r.custom()
	}
	if r.mitmHost != nil {
		return r.runMITM()
	}
	traffic := stats.DefaultStore.OpenDeviceConnection(r.statsPath, r.fallback, r.deviceMAC)
	defer func() { err = errors.Join(err, traffic.Close()) }()

	handled, err := r.trySplice(traffic)
	if !handled && err == nil {
		err = relayTCP(r.lConn, r.rConn, traffic, 10*time.Second, r.outboundOrigin, r.policyLease, r.routeLease)
	} else {
		err = withoutCleanupErrors(err)
	}
	if recordDataPlaneError(r.dialer, r.statsPath, err) {
		return err
	}
	return nil
}

func (r *tcpRelay) runMITM() error {
	lease := netproxy.NewLease(netproxy.NewResourceRef())
	defer lease.Invalidate(net.ErrClosed)
	stop := watchAbort(lease, r.policyLease, r.routeLease, func() {
		lease.Abort(connectionAbortCause(lease, r.policyLease, r.routeLease))
		setTCPResetOnClose(r.lConn)
		_ = r.lConn.Close()
	})
	defer stop()
	return r.mitmHost.ServeConn(r.lConn, plugin.Flow{Host: r.domain, Port: r.dst.Port(), SourceMAC: r.deviceMAC}, mitmPlannerWithLease(r.mitmPlanner, lease))
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

type tcpCopyResult struct {
	err        error
	needsDrain bool
}

func relayEndpointDirection(dst, src *relayEndpoint, add func(uint64)) error {
	return copyRelay(&trafficWriter{Writer: dst, add: add}, src)
}

func copyTCPDirection(dst, src *relayEndpoint, add func(uint64), abortCause func() error) tcpCopyResult {
	outcome := tcpCopyResult{err: relayEndpointDirection(dst, src, add)}
	// copyRelay consumes read EOF. Propagate FIN only while the owner
	// still allows it; resource cleanup can itself surface as EOF.
	if outcome.err == nil && abortCause() == nil {
		outcome.needsDrain, outcome.err = dst.halfClose()
	}
	return outcome
}

// relayTCP owns two copy workers. EOF half-closes the destination; a failure or
// owner abort closes both endpoints and waits for both workers to finish.
func relayTCP(lConn, rConn net.Conn, traffic *stats.Connection, drainTimeout time.Duration, origin netproxy.FailureOrigin, policyLease, routeLease *netproxy.Lease) error {
	results := make(chan tcpCopyResult, 2)
	left := &relayEndpoint{conn: lConn, origin: netproxy.OriginCaller}
	right := &relayEndpoint{conn: rConn, origin: origin}
	lease := netproxy.DependencyOf(rConn)
	invalidated := lease.Done()
	policyChanged := policyLease.Done()
	routeChanged := routeLease.Done()
	abortCause := func() error { return connectionAbortCause(lease, policyLease, routeLease) }
	copyDirection := func(dst, src *relayEndpoint, add func(uint64)) {
		// Keep CloseWrite in the worker: an owner abort must be able to
		// interrupt it if sending FIN blocks.
		results <- copyTCPDirection(dst, src, add, abortCause)
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
	stopped := false
	var causes []error
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		timeout = nil
		invalidated = nil
		policyChanged = nil
		routeChanged = nil
		// Check the owner signal even if a copy result won the select race.
		if cause := abortCause(); cause != nil {
			causes = append(causes, cause)
			setTCPResetOnClose(lConn)
		}
		// Unblock both reads and writes, including a reverse copy blocked
		// writing to the endpoint whose read side has already ended.
		_ = left.close()
		_ = right.close()
	}
	for remaining := 2; remaining > 0; {
		select {
		case <-routeChanged:
			routeChanged = nil
			if abortCause() != nil {
				stop()
			}
		case <-policyChanged:
			policyChanged = nil
			if abortCause() != nil {
				stop()
			}
		case <-invalidated:
			invalidated = nil
			if abortCause() != nil {
				stop()
			}
		case outcome := <-results:
			remaining--
			causes = append(causes, outcome.err)
			if outcome.err != nil || abortCause() != nil {
				stop()
			} else if outcome.needsDrain && remaining == 1 && !stopped {
				// A connection without CloseWrite cannot propagate EOF. Give
				// the reverse copy a fixed grace period after the first EOF.
				timer = time.NewTimer(drainTimeout)
				timeout = timer.C
			}
		case <-timeout:
			// This is our bounded EOF drain, not a failed upstream operation.
			// Keep independent I/O and owner failures collected during cleanup.
			stop()
		}
	}
	return withoutCleanupErrors(errors.Join(causes...))
}
