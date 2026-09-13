// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"testing"
	"time"
)

// Established-endpoint activity, including timestamp acquisition, without I/O.
func BenchmarkUDPIdleRefresh(b *testing.B) {
	b.Run("endpoint", func(b *testing.B) {
		p := new(UdpEndpointPool)
		e := &UdpEndpoint{NatTimeout: time.Hour}
		key := netip.MustParseAddrPort("192.0.2.1:1234")
		p.refreshTimer(key, e, time.Now())
		defer e.deadlineTimer.Stop()
		b.ReportAllocs()
		for b.Loop() {
			p.refreshTimer(key, e, time.Now())
		}
	})
	b.Run("anyfrom", func(b *testing.B) {
		a := &Anyfrom{idleTTL: time.Hour, idleEvictTimer: time.AfterFunc(time.Hour, func() {})}
		defer a.idleEvictTimer.Stop()
		b.ReportAllocs()
		for b.Loop() {
			a.refreshIdleDeadline()
		}
	})
}
