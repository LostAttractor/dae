package control

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type tcpRelay struct {
	lConn  net.Conn
	rConn  net.Conn
	dst    netip.AddrPort
	domain string

	// Ordinary relay dependencies and accounting.
	monitor        *tcpRelayMonitor
	direct         bool
	dialer         *dialer.Dialer
	outboundOrigin netproxy.FailureOrigin
	statsPath      stats.Path
	deviceMAC      [6]byte
	fallback       bool
	routeLease     *netproxy.Lease
	policyLease    *netproxy.Lease
	ownerLease     *netproxy.Lease
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

	err = r.copyTCP(traffic, 10*time.Second)
	reporter := r.dialer
	if r.direct {
		// Native io.Copy retains errno and direction but cannot reliably say
		// which peer failed. A direct connection must not recover a proxy node.
		reporter = nil
	}
	if recordDataPlaneError(reporter, r.statsPath, err) {
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

// copyTCP coordinates the two copy workers independently of their copy method.
// EOF half-closes the destination; failures and owner aborts close both endpoints.
func (r *tcpRelay) copyTCP(traffic *stats.Connection, drainTimeout time.Duration) error {
	pair := newTCPCopyPair(r, traffic)
	var leaseDone [len(pair.leases)]<-chan struct{}
	for i, lease := range pair.leases {
		leaseDone[i] = lease.Done()
	}
	if !r.monitor.register(pair.progress) {
		pair.close()
		return net.ErrClosed
	}
	defer r.monitor.remove(pair.progress)
	results := make(chan tcpCopyResult, 2)
	go func() { results <- pair.copy(1) }()
	go func() { results <- pair.copy(0) }()

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
		leaseDone = [len(pair.leases)]<-chan struct{}{}
		// Check the owner signal even if a copy result won the select race.
		if cause := pair.abortCause(); cause != nil {
			causes = append(causes, cause)
			setTCPResetOnClose(r.lConn)
		}
		// Unblock both reads and writes, including a reverse copy blocked
		// writing to the endpoint whose read side has already ended.
		pair.close()
	}
	// Retiring a lease lets the relay finish; only an abort cause stops it.
	leaseChanged := func(i int) {
		leaseDone[i] = nil
		if pair.abortCause() != nil {
			stop()
		}
	}
	for remaining := 2; remaining > 0; {
		select {
		case <-leaseDone[0]:
			leaseChanged(0)
		case <-leaseDone[1]:
			leaseChanged(1)
		case <-leaseDone[2]:
			leaseChanged(2)
		case <-leaseDone[3]:
			leaseChanged(3)
		case outcome := <-results:
			remaining--
			causes = append(causes, outcome.err)
			if outcome.err != nil || pair.abortCause() != nil {
				stop()
			} else if outcome.needsDrain && remaining == 1 && !stopped {
				// A connection without CloseWrite cannot propagate EOF. Give
				// the reverse copy a fixed grace period after the first EOF.
				timer = time.NewTimer(drainTimeout)
				timeout = timer.C
			}
		case <-pair.progress.idle:
			if !stopped && r.monitor.confirmIdle(pair.progress) {
				stop()
			}
		case <-timeout:
			// This is our bounded EOF drain, not a failed upstream operation.
			// Keep independent I/O and owner failures collected during cleanup.
			stop()
		}
	}
	return withoutCleanupErrors(errors.Join(causes...))
}
