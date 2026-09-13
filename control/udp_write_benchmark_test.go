// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// Exercise the established UDP write path with the dispatcher's per-packet
// deadline, excluding transport I/O and queue scheduling.
func BenchmarkUDPWrite(b *testing.B) {
	conn := newTestPacketConn(false)
	defer conn.Close()
	endpoint := &UdpEndpoint{conn: conn}
	plane := &ControlPlane{}
	source := netip.MustParseAddrPort("192.0.2.1:1234")
	destination := netip.MustParseAddrPort("192.0.2.2:443")
	payload := []byte("packet")
	b.ReportAllocs()
	for b.Loop() {
		ctx, cancel := context.WithDeadline(b.Context(), time.Now().Add(consts.DefaultDialTimeout))
		err := plane.writeUDP(ctx, endpoint, source, destination, payload)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
	}
}
