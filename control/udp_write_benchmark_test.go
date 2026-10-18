// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
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
	for _, socketDeadline := range []bool{false, true} {
		b.Run(fmt.Sprintf("socket-deadline=%t", socketDeadline), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				deadline := time.Now().Add(consts.DefaultDialTimeout)
				var err error
				if socketDeadline {
					err = plane.writeUDPUntil(b.Context(), deadline, endpoint, source, destination, payload)
				} else {
					ctx, cancel := context.WithDeadline(b.Context(), deadline)
					err = plane.writeUDP(ctx, endpoint, source, destination, payload)
					cancel()
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
