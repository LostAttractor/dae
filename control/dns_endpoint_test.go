// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/component/outbound"
)

func TestDNSUpstreamHostnamePolicy(t *testing.T) {
	noDial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("selection test must not dial")
	}
	groups := []*outbound.DialerGroup{downloadTestGroup(t, "direct", noDial), downloadTestGroup(t, "block", noDial), downloadTestGroup(t, "proxy", noDial)}
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "sip(192.0.2.1) && domain(full:dns.example) -> proxy(mark:37)"))
	c := &ControlPlane{outbounds: groups, routingMatcher: matcher, dialTargetOverride: true}
	for _, network := range []string{"udp", "tcp"} {
		for _, original := range []string{"192.0.2.53:53", "192.0.2.54:53"} {
			identity := bpfRoutingResult{CaptureFlags: 8, Mark: 11}
			q, _, err := c.dnsRequest(dnsTestRequest(t, "client-question.example.", 1).Wire, network, netip.MustParseAddrPort("192.0.2.1:2345"), netip.MustParseAddrPort(original), identity)
			if err != nil {
				t.Fatal(err)
			}
			option, err := c.dnsDialOption(t.Context(), network, "192.0.2.54:53", "dns.example", q, identity)
			if err != nil {
				t.Fatal(err)
			}
			if option.Outbound.Name != "proxy" || option.Mark != 37 || option.DialTarget != "192.0.2.54:53" {
				t.Fatalf("lost hostname/source/mark or selected IP: %+v", option)
			}
			// A bare IP and a literal-IP hostname retain the ingress decision
			// when the destination and transport are unchanged.
			for _, hostname := range []string{"", q.Destination.Addr().String()} {
				option, err = c.dnsDialOption(t.Context(), network, q.Destination.String(), hostname, q, identity)
				if err != nil {
					t.Fatal(err)
				}
				if option.Outbound.Name != "direct" || option.Mark != 11 {
					t.Fatalf("nameless DNS lost kernel decision: %+v", option)
				}
			}
		}
	}
}
