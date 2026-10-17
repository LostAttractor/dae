// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func BenchmarkAutomaticSelectionDemand(b *testing.B) {
	for _, size := range []int{16, 256} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			g := &DialerGroup{Name: b.Name(), selectionPolicy: dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}.WithDefaults(), dialerToAnnotation: make(map[*dialer.Dialer]*dialer.Annotation)}
			for i := range size {
				d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: fakeDialer{}}), &dialer.GlobalOption{}, &dialer.Property{Name: strconv.Itoa(i)}, false, "")
				g.Dialers = append(g.Dialers, d)
				g.dialerToAnnotation[d] = &dialer.Annotation{Priority: i % 2}
			}
			g.automatic = newAutomaticSelection(g, 0)
			for i := range g.automatic.selected {
				g.automatic.selected[i] = g.Dialers[1]
			}
			b.Cleanup(func() { _ = g.Close() })
			b.ReportAllocs()
			for b.Loop() {
				g.automatic.refreshDemandLocked()
			}
		})
	}
}
