// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"io"
	"testing"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/sniffing"
)

// Measure the relay's per-connection bookkeeping without kernel connection
// establishment or bulk transfer dominating its allocations and worker costs.
func BenchmarkTCPRelayLifecycle(b *testing.B) {
	path := stats.Path{Dialer: b.Name()}
	b.ReportAllocs()
	for b.Loop() {
		left, right := relayTestNewConn(), relayTestNewConn()
		left.read = func([]byte) (int, error) { return 0, io.EOF }
		right.read = left.read
		sniffer := sniffing.NewConnSniffer(left, 0)
		_, _ = sniffer.SniffTcp()
		relay := &tcpRelay{lConn: sniffer, rConn: right, statsPath: path}
		if err := relay.run(); err != nil {
			b.Fatal(err)
		}
	}
}
