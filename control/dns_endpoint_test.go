// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// dnsTestOutbounds supplies the builtin groups that DNS egress selection needs.
func dnsTestOutbounds(t *testing.T) []*outbound.DialerGroup {
	noDial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected DNS dial") }
	return []*outbound.DialerGroup{downloadTestGroup(t, "direct", noDial), downloadTestGroup(t, "block", noDial)}
}

func TestDNSUpstreamHostnamePolicy(t *testing.T) {
	noDial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("selection test must not dial")
	}
	groups := []*outbound.DialerGroup{downloadTestGroup(t, "direct", noDial), downloadTestGroup(t, "block", noDial), downloadTestGroup(t, "proxy", noDial)}
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "sip(192.0.2.1) && domain(full:dns.example) -> proxy(mark:37)"))
	c := &ControlPlane{outbounds: groups, routingMatcher: matcher, dialTargetOverride: true}
	for _, network := range []string{"udp", "tcp"} {
		for _, original := range []string{"192.0.2.53:53", "192.0.2.54:53"} {
			identity := routingResult{CaptureFlags: captureDNS, Mark: 11}
			q, _, err := c.dnsRequest(dnsTestWire(t, dnsTestRequest(t, "client-question.example.", 1)), network, netip.MustParseAddrPort("192.0.2.1:2345"), netip.MustParseAddrPort(original), identity)
			if err != nil {
				t.Fatal(err)
			}
			option, err := c.dnsUpstreamOption(t.Context(), network, "192.0.2.54:53", "dns.example", q, identity)
			if err != nil {
				t.Fatal(err)
			}
			if option.Outbound.Name != "proxy" || option.Mark != 37 || option.DialTarget != "192.0.2.54:53" {
				t.Fatalf("lost hostname/source/mark or selected IP: %+v", option)
			}
			// A bare IP and a literal-IP hostname retain the ingress decision
			// when the destination and transport are unchanged.
			for _, hostname := range []string{"", q.Destination.Addr().String()} {
				option, err = c.dnsUpstreamOption(t.Context(), network, q.Destination.String(), hostname, q, identity)
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

// A resolver's egress is its node path, shared by every group selecting it,
// or direct traffic with its effective mark.
func TestDNSEgressFollowsNodeAndMark(t *testing.T) {
	c := &ControlPlane{soMarkFromDae: 7}
	unused := func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	a, sameA, b := downloadTestGroup(t, "a", unused), downloadTestGroup(t, "a", unused), downloadTestGroup(t, "b", unused)
	if c.dnsEgress(a, a.Dialers[0], false, 0) != c.dnsEgress(sameA, sameA.Dialers[0], false, 37) {
		t.Fatal("groups or routing marks split one proxy path")
	}
	if c.dnsEgress(a, a.Dialers[0], false, 0) == c.dnsEgress(b, b.Dialers[0], false, 0) {
		t.Fatal("different proxy paths share an egress")
	}
	if c.dnsEgress(nil, nil, true, 0) != c.dnsEgress(nil, nil, true, 7) || c.dnsEgress(nil, nil, true, 7) == c.dnsEgress(nil, nil, true, 8) {
		t.Fatal("direct egress ignores its effective mark")
	}
}

// A random group's traffic takes any member, so its answers stand for the
// member set: shared by its nodes, separate once the membership changes. A
// group with one selected node keeps that node's identity.
func TestDNSEgressOfRandomGroupIsItsMembers(t *testing.T) {
	c := new(ControlPlane)
	option := &dialer.GlobalOption{}
	group := func(policy consts.DialerSelectionPolicy, links ...string) *outbound.DialerGroup {
		var nodes []*dialer.Dialer
		var annotations []*dialer.Annotation
		for _, link := range links {
			runtime := netproxy.NewRuntime(netproxy.Layer{Data: downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })})
			nodes = append(nodes, dialer.NewDialer(runtime, option, &dialer.Property{Name: link, Link: "test://" + link}, true, ""))
			annotations = append(annotations, &dialer.Annotation{})
		}
		g := outbound.NewDialerGroup(option, "proxy", outbound.GroupKindSelector, nodes, annotations, dialer.DialerSelectionPolicy{Policy: policy})
		t.Cleanup(func() { _ = g.Close() })
		return g
	}
	random, reordered := group(consts.DialerSelectionPolicy_Random, "hk", "jp"), group(consts.DialerSelectionPolicy_Random, "jp", "hk")
	egress := c.dnsEgress(random, random.Dialers[0], false, 0)
	if egress != c.dnsEgress(random, random.Dialers[1], false, 0) || egress != c.dnsEgress(reordered, reordered.Dialers[0], false, 0) {
		t.Fatal("a random group's members split its answers")
	}
	grown := group(consts.DialerSelectionPolicy_Random, "hk", "jp", "us")
	if egress == c.dnsEgress(grown, grown.Dialers[0], false, 0) {
		t.Fatal("changed membership kept the answers")
	}
	failover := group(consts.DialerSelectionPolicy_Failover, "hk", "jp")
	single := group(consts.DialerSelectionPolicy_Random, "hk")
	if c.dnsEgress(failover, failover.Dialers[0], false, 0) == c.dnsEgress(failover, failover.Dialers[1], false, 0) ||
		c.dnsEgress(failover, failover.Dialers[0], false, 0) != c.dnsEgress(single, single.Dialers[0], false, 0) {
		t.Fatal("a selected node lost its identity")
	}
}
