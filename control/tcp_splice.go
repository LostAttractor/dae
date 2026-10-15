// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// nativeTCPPair probes both sockets before consuming any data. Only Runtime
// lifetime and accepted-sniffer wrappers can be bypassed; protocol adapters,
// MPTCP and unavailable counters stay on the ordinary copy path.
func nativeTCPPair(lConn, rConn net.Conn) (conns [2]*net.TCPConn, counters [2]func() (uint64, error)) {
	left, ok := unwrapSniffer(lConn).(*net.TCPConn)
	right := netproxy.NativeTCPConn(rConn)
	if !ok || right == nil {
		return conns, counters
	}
	upload, err := tcpWriteCounter(right)
	if err != nil {
		return conns, counters
	}
	download, err := tcpWriteCounter(left)
	if err != nil {
		return conns, counters
	}
	return [2]*net.TCPConn{left, right}, [2]func() (uint64, error){upload, download}
}

func copyNativeTCP(dst, src *net.TCPConn, original net.Conn) (uint64, error) {
	var prefix uint64
	if sniffer, ok := original.(sniffing.ConnSnifferInterface); ok {
		// Both workers already run while this potentially blocking write flushes
		// sniffed data. Count partial writes even when flushing fails.
		err := sniffer.WriteBufferedTo(&trafficWriter{Writer: dst, add: func(n uint64) { prefix += n }})
		if err != nil {
			return prefix, err
		}
	}
	n, err := io.Copy(dst, src)
	return prefix + uint64(n), err
}

// nativeCopyFailure attributes a plain closed-socket error to local cleanup when
// an owner abort or our own close caused it.
func nativeCopyFailure(err error, index int, local bool) error {
	if err == nil {
		return nil
	}
	origin := netproxy.FailureOrigin("")
	if local && plainClosedError(err) {
		origin = netproxy.OriginLocalCleanup
	}
	direction := "upload"
	if index == 1 {
		direction = "download"
	}
	return netproxy.WrapFailure(fmt.Errorf("TCP %s: %w", direction, err), netproxy.Failure{Origin: origin, Scope: netproxy.ScopeOperation})
}
