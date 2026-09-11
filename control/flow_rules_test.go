// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func prepareFlowRulesForTest(t *testing.T, controls, routes string) preparedRules {
	t.Helper()
	sections, err := config_parser.Parse("global {}\nrules {\n" + controls + "\n}\nrouting {\n" + routes + "\nfallback: direct\n}")
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepareRoutingRules(context.Background(), &c.Routing, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.enableFlowRules(context.Background(), c.Rules, nil); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFlowRulesPreserveOutboundAndDirect(t *testing.T) {
	mustRule := "sip(192.0.2.0/24) && port(53, 443) -> must"
	bumpRule := "domain(full: api.example.com) && l4proto(tcp) && dport(443) -> bump"
	for _, controls := range []string{mustRule + "\n" + bumpRule, bumpRule + "\n" + mustRule} {
		prepared := prepareFlowRulesForTest(t, controls, `
ip(10.0.0.0/8) -> direct
domain(full: api.example.com) -> proxy(mark: 37)
dport(80) -> block`)
		matcher, builder := routingMatcherForTest(t, prepared)
		for _, rule := range builder.rules {
			if ((rule.Flags >> 3) & 3) != 0 {
				t.Fatal("must/bump introduced implicit capture")
			}
		}
		for _, test := range []struct {
			name, source, destination, domain string
			proto                             consts.L4ProtoType
			kernel, userspace                 consts.OutboundIndex
			mark                              uint32
			must                              bool
		}{
			{"SSH", "192.0.2.1", "10.0.0.1:22", "", consts.L4ProtoType_TCP, consts.OutboundDirect, consts.OutboundDirect, 0, false},
			{"unrelated HTTPS", "192.0.2.1", "198.51.100.1:443", "outside.example", consts.L4ProtoType_TCP, consts.OutboundDirect, consts.OutboundDirect, 0, true},
			{"missing DNS", "192.0.2.1", "198.51.100.1:443", "", consts.L4ProtoType_TCP, consts.OutboundDirect, consts.OutboundDirect, 0, true},
			{"bump and must", "192.0.2.1", "198.51.100.1:443", "api.example.com", consts.L4ProtoType_TCP, consts.OutboundControlPlaneRouting, consts.OutboundUserDefinedMin, 37, true},
			{"bump only", "203.0.113.1", "198.51.100.1:443", "api.example.com", consts.L4ProtoType_TCP, consts.OutboundControlPlaneRouting, consts.OutboundUserDefinedMin, 37, false},
			{"DNS must", "192.0.2.1", "198.51.100.1:53", "", consts.L4ProtoType_UDP, consts.OutboundDirect, consts.OutboundDirect, 0, true},
			{"wrong protocol", "192.0.2.1", "198.51.100.1:443", "api.example.com", consts.L4ProtoType_UDP, consts.OutboundUserDefinedMin, consts.OutboundUserDefinedMin, 37, true},
			{"block", "192.0.2.1", "198.51.100.1:80", "", consts.L4ProtoType_TCP, consts.OutboundBlock, consts.OutboundBlock, 0, false},
		} {
			t.Run(test.name, func(t *testing.T) {
				src := netip.MustParseAddr(test.source).As16()
				destination := netip.MustParseAddrPort(test.destination)
				dst := destination.Addr().As16()
				bitmap := matcher.domainMatcher.MatchDomainBitmap(test.domain)
				for _, kernel := range []bool{false, true} {
					var bitmaps [][]uint32
					want, wantMark := test.userspace, test.mark
					if kernel {
						bitmaps = [][]uint32{bitmap, bitmap}
						want = test.kernel
						if want == consts.OutboundControlPlaneRouting {
							wantMark = 0 // Selected during userspace rerouting.
						}
					}
					got, mark, must, err := matchTestRouting(matcher, src[:], dst[:], 12345, destination.Port(), consts.IpVersion_4, test.proto, test.domain, [16]uint8{}, 0, 0, make([]byte, 16), bitmaps...)
					if err != nil || got != want || mark != wantMark || must != test.must {
						t.Fatalf("kernel=%v: got=(%v,%d,%v) err=%v; want=(%v,%d,%v)", kernel, got, mark, must, err, want, wantMark, test.must)
					}
				}
			})
		}
	}
}

func TestFlowRulesComposeWithCaptureAndAPIBypass(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, `
dport(443) -> bump
dport(443) -> dnat(198.51.100.20)
dport(443) -> must`, "")
	prepared.enableMITMPlan(mitmRoutingPlugin("api.example.com").Plan())
	prepared.bypassAPI(443, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	matcher, _ := routingMatcherForTest(t, prepared)
	// Destination candidates hand off before any controls for the old target.
	for _, destination := range []string{"10.0.0.1", "198.51.100.1"} {
		address := netip.MustParseAddr(destination)
		bitmap := matcher.domainMatcher.MatchDomainBitmap("api.example.com")
		got, err := matcher.evaluateSpans(matcher.profiles[matcher.defaultProfileID], routingInput{
			src: netip.AddrPortFrom(address, 12345), dst: netip.AddrPortFrom(address, 443),
			l4proto:      consts.L4ProtoType_TCP,
			domainBitmap: bitmap, domainBumpBitmap: bitmap,
		})
		want, flags := consts.OutboundControlPlaneRouting, captureDestination
		if destination == "10.0.0.1" {
			want, flags = consts.OutboundDirect, 0
		}
		if err != nil || got.outbound != want || got.must || got.captureFlags != flags {
			t.Fatalf("%s: got=%+v err=%v, want=%v capture=%d", destination, got, err, want, flags)
		}
	}
}
