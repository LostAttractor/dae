// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// Measure startup/reload construction costs, without socket or DNS latency.
func BenchmarkEntryResolver(b *testing.B) {
	for _, test := range []struct{ name, server string }{
		{"system", ""}, {"loopback", "127.0.0.53"}, {"external", "192.0.2.53"},
	} {
		b.Run(test.name, func(b *testing.B) {
			path := &PathSpec{Entry: EntryOptions{Interface: "cu"}}
			option := &dialer.GlobalOption{SoMarkFromDae: 0x100, DNSResolver: test.server}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := path.entryResolver(option); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
