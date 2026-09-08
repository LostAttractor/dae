// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

// The same valid bytecode fixtures measure predicate preparation separately
// from traversal. Validate the result before timing each packet path.
func BenchmarkRoutingMatcher(b *testing.B) {
	for _, count := range []int{16, 1024} {
		for _, scenario := range []string{"port-sequential", "domain-miss", "mixed-lpm", "and-short-circuit", "or-short-circuit"} {
			b.Run(fmt.Sprintf("%s/rules=%d", scenario, count), func(b *testing.B) {
				builder := newRoutingMatcherBuilder(nil, nil, nil)
				builder.rules = make([]bpfMatchSet, count)
				builder.routing.end = count
				builder.defaultProfileID = 1
				builder.profiles = []routingProfile{{ID: 1, Spans: []routingSpan{{End: uint32(count)}}}}
				builder.simulatedLpmTries = [][]netip.Prefix{{netip.MustParsePrefix("198.18.0.0/15")}}
				builder.simulatedDomainSet = []routing.DomainSet{{Key: consts.RoutingDomainKey_Full, Domains: []string{"target.example"}}}
				for i := range builder.rules[:count-1] {
					builder.rules[i] = bpfMatchSet{Type: uint8(consts.MatchType_Port), Value: _bpfPortRange{PortStart: 1, PortEnd: 1}.Encode(), Outbound: 1}
				}
				builder.rules[count-1] = bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Mark: 37}
				switch scenario {
				case "domain-miss":
					for i := range builder.rules[:count-1] {
						builder.rules[i] = bpfMatchSet{Type: uint8(consts.MatchType_DomainSet), Outbound: 1}
					}
				case "mixed-lpm":
					kinds := []consts.MatchType{consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac}
					for i := range builder.rules[:count-1] {
						builder.rules[i] = bpfMatchSet{Type: uint8(kinds[i%len(kinds)]), Outbound: 1}
					}
				case "and-short-circuit":
					for i := range builder.rules[:count-2] {
						builder.rules[i].Action = uint8(consts.MatchActionAnd)
					}
				case "or-short-circuit":
					for i := range builder.rules[:count-2] {
						builder.rules[i].Action = uint8(consts.MatchActionOr)
					}
					builder.rules[0].Value = _bpfPortRange{PortStart: 443, PortEnd: 443}.Encode()
					builder.rules[count-2].Outbound, builder.rules[count-2].Mark = 0, 37
				}
				if err := builder.validate(); err != nil {
					b.Fatal(err)
				}
				matcher, err := builder.BuildUserspace()
				if err != nil {
					b.Fatal(err)
				}
				input := routingInput{src: netip.MustParseAddrPort("192.0.2.1:12345"), dst: netip.MustParseAddrPort("198.51.100.1:443"), l4proto: consts.L4ProtoType_TCP, domain: "outside.example"}
				check := func() {
					outbound, mark, must, err := matcher.match(input)
					if err != nil || outbound != consts.OutboundDirect || mark != 37 || must {
						b.Fatalf("routing result: %d/%d/%t, %v", outbound, mark, must, err)
					}
				}
				check()
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					check()
				}
			})
		}
	}
}
