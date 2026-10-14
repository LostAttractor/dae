// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"io"
	"net"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
)

// tcpCopyPair keeps the original endpoints for ownership and protocol errors,
// and optionally native sockets for copying. Index 0 is upload, 1 is download.
// Both strategies share settlement, half-close and abort semantics.
type tcpCopyPair struct {
	endpoints [2]relayEndpoint
	native    [2]*net.TCPConn
	progress  *tcpRelayProgress
	leases    [4]*netproxy.Lease // outbound resource, group, route, accepted socket
}

func newTCPCopyPair(r *tcpRelay, traffic *stats.Connection) *tcpCopyPair {
	p := &tcpCopyPair{
		endpoints: [2]relayEndpoint{{conn: r.lConn, origin: netproxy.OriginCaller}, {conn: r.rConn, origin: r.outboundOrigin}},
		progress:  newTCPRelayProgress(traffic),
		leases:    [4]*netproxy.Lease{netproxy.DependencyOf(r.rConn), r.policyLease, r.routeLease, r.ownerLease},
	}
	if r.direct {
		var counters [2]func() (uint64, error)
		if p.native, counters = nativeTCPPair(r.lConn, r.rConn); p.native[0] != nil {
			// Native copies bypass the sniffer; the monitor reports their activity.
			p.progress.directions[0].read, p.progress.directions[1].read = counters[0], counters[1]
			p.progress.activity = r.activity
		}
	}
	return p
}

func (p *tcpCopyPair) abortCause() error { return connectionAbortCause(p.leases[:]...) }

func (p *tcpCopyPair) close() {
	_ = p.endpoints[0].close()
	_ = p.endpoints[1].close()
}

type tcpCopyResult struct {
	err        error
	needsDrain bool
}

func (p *tcpCopyPair) copy(index int) tcpCopyResult {
	src, dst := &p.endpoints[index], &p.endpoints[1-index]
	var outcome tcpCopyResult
	if p.native[0] != nil {
		n, err := copyNativeTCP(p.native[1-index], p.native[index], src.conn)
		p.progress.complete(index, n)
		local := p.abortCause() != nil || dst.closed.Load() || src.closed.Load()
		outcome.err = nativeCopyFailure(err, index, local)
	} else {
		outcome.err = relayEndpointDirection(dst, src, func(n uint64) { p.progress.record(index, n) })
	}
	// Settle counters before FIN. Keep CloseWrite in the worker so an abort
	// can interrupt it, just like a blocked read or write.
	if outcome.err == nil && p.abortCause() == nil {
		outcome.needsDrain, outcome.err = dst.halfClose()
		if outcome.err == nil {
			p.progress.halfClose()
		}
	}
	return outcome
}

type trafficWriter struct {
	io.Writer
	add func(uint64)
}

func (w *trafficWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	if n > 0 {
		w.add(uint64(n))
	}
	return n, err
}

func relayEndpointDirection(dst, src *relayEndpoint, add func(uint64)) error {
	return copyRelay(&trafficWriter{Writer: dst, add: add}, src)
}
