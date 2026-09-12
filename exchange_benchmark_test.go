// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"net"
	"net/netip"
	"testing"

	policy "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae/common/netutils"
	dns "github.com/miekg/dns"
)

// Measure the actual per-query router lifetime with an in-memory stream. This
// includes socket/worker setup but excludes network and encrypted handshakes.
func BenchmarkExchangeTCP(b *testing.B) {
	request := safetyRequest(dns.TypeA)
	request.DialContext = func(context.Context, string, string, string) (net.Conn, error) {
		c, p := net.Pipe()
		go func() {
			defer p.Close()
			dc := &dns.Conn{Conn: p}
			q, err := dc.ReadMsg()
			if err == nil {
				_ = dc.WriteMsg(new(dns.Msg).SetReply(q))
			}
		}()
		return c, nil
	}
	upstream := &policy.Upstream{Scheme: "tcp", Hostname: "192.0.2.53", Port: 53,
		Ip46: &netutils.Ip46{Ip4: netip.MustParseAddr("192.0.2.53")}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Exchange(b.Context(), request, upstream); err != nil {
			b.Fatal(err)
		}
	}
}
