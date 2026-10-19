// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"io"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/logger"
	log "github.com/sirupsen/logrus"
)

// Includes field assembly, logrus entry copies and formatting. Discard only
// removes sink I/O so disk or terminal speed cannot mask allocation changes.
func BenchmarkLogDial(b *testing.B) {
	l := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := l.Out, l.Formatter, l.GetLevel()
	b.Cleanup(func() {
		l.SetOutput(oldOutput)
		l.SetFormatter(oldFormatter)
		l.SetLevel(oldLevel)
	})
	l.SetOutput(io.Discard)
	l.SetFormatter(logger.NewTextFormatter(false))
	l.SetLevel(log.InfoLevel)
	c := new(ControlPlane)
	source := netip.MustParseAddrPort("192.0.2.1:12345")
	destination := netip.MustParseAddrPort("198.51.100.2:443")
	option := &DialOption{
		DialTarget: "example.org:443", Dialer: &dialer.Dialer{Property: &dialer.Property{Name: "node-a"}},
		Outbound: &outbound.DialerGroup{Name: "proxy", TargetKind: outbound.TargetKindGroup},
	}
	for _, workload := range []string{"forward", "reroute", "escaped"} {
		b.Run(workload, func(b *testing.B) {
			route := &routingResult{}
			domain := "example.org"
			if workload == "reroute" {
				route.Outbound = uint8(consts.OutboundControlPlaneRouting)
				route.Pid, route.Dscp = 1234, 8
				copy(route.Pname[:], "test-process")
			}
			if workload == "escaped" {
				domain = "remote\x1b]52;c;YWJj\a\r\u009b2J"
			}
			b.ReportAllocs()
			for b.Loop() {
				c.logDial(source, destination, domain, option, "tcp4", route)
			}
		})
	}
}
