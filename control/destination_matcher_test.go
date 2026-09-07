package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"slices"
)

func destinationTestMatcher(t *testing.T, text string) (*RoutingMatcher, *RoutingMatcherBuilder) {
	t.Helper()
	sections, err := config_parser.Parse("rules {\n" + text + "\n}")
	if err != nil {
		t.Fatal(err)
	}
	var rules config.Rules
	for _, s := range sections {
		for _, i := range s.Items {
			rules.Rules = append(rules.Rules, i.Value.(*config_parser.RoutingRule))
		}
	}
	r, err := rules.Destinations()
	if err != nil {
		t.Fatal(err)
	}
	r, err = prepareDestinationRules(context.Background(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRoutingMatcherBuilder(nil, map[string]uint8{"direct": 0, "block": 1}, nil, "direct", nil, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	return m, b
}

func TestDestinationPredicateOriginalIdentity(t *testing.T) {
	m, _ := destinationTestMatcher(t, `
domain(full: api.example.com) && sip(192.0.2.0/24) && dport(443) -> dnat('2001:db8::20')
!domain(suffix: example.com) && l4proto(tcp) -> dnat(198.51.100.21)
dip(192.0.2.10) -> dnat(198.51.100.22)
dip(198.51.100.22) -> dnat(198.51.100.23)`)
	for _, test := range []struct {
		domain, src string
		port        uint16
		want        string
	}{
		{"api.example.com", "192.0.2.1:12345", 443, "[2001:db8::20]:443"},
		{"outside.test", "192.0.2.1:12345", 443, "198.51.100.21:443"},
		{"", "192.0.2.1:12345", 443, "198.51.100.22:443"}, // unknown != negative match
		{"api.example.com", "203.0.113.1:12345", 443, "198.51.100.22:443"},
		{"api.example.com", "192.0.2.1:12345", 80, "198.51.100.22:80"},
	} {
		p := &RouteParam{Src: netip.MustParseAddrPort(test.src), Dest: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), test.port), Domain: test.domain, routingResult: &bpfRoutingResult{CaptureFlags: captureDestination}, networkType: *common.NetworkTCP4.NetworkType()}
		decision, err := m.matchDestination(p)
		if err != nil {
			t.Fatal(err)
		}
		p.destination = decision
		if decision.String() != test.want {
			t.Errorf("%+v => %+v", test, decision)
		}
		if got := p.dialTarget(true); got != test.want {
			t.Fatal("domain dial override replaced DNAT")
		}
		src, dst := p.Src.Addr().As16(), p.Dest.Addr().As16()
		out, _, _, err := m.Match(src[:], dst[:], p.Src.Port(), p.Dest.Port(), consts.IpVersion_4, consts.L4ProtoType_TCP, p.Domain, [16]uint8{}, 0, 0, make([]byte, 16))
		if err != nil || out != consts.OutboundDirect {
			t.Fatalf("DNAT changed ordinary routing: %v %v", out, err)
		}
	}
}

func TestDestinationDynamicClientAndCandidate(t *testing.T) {
	m, b := destinationTestMatcher(t, `!domain(full: excluded.example) && client(kids) && dport(443) -> dnat(198.51.100.9)`)
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: netip.MustParseAddrPort("192.0.2.2:443"), Domain: "allowed.example", routingResult: &bpfRoutingResult{Mac: mac}, networkType: *common.NetworkTCP4.NetworkType()}
	for _, joined := range []bool{false, true, false} {
		var members [][6]byte
		if joined {
			members = append(members, mac)
		}
		if err := b.SetClientMembers(m, "kids", members, false); err != nil {
			t.Fatal(err)
		}
		decision, err := m.matchDestination(p)
		if err != nil || decision.IsValid() != joined {
			t.Fatalf("joined=%v decision=%+v err=%v", joined, decision, err)
		}
	}
	if err := b.SetClientMembers(m, "kids", [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	// Materialize only the kernel candidate as a normal test terminal. Domain
	// is intentionally unavailable; all remaining metadata still constrains it.
	for i := range b.rules {
		if b.rules[i].CaptureFlags&captureDestination != 0 {
			b.rules[i].CaptureFlags = 0
			b.rules[i].Action = uint8(consts.MatchActionRoute)
			b.rules[i].Outbound = 2
		}
	}
	src, dst := p.Src.Addr().As16(), p.Dest.Addr().As16()
	var mac16 [16]byte
	copy(mac16[10:], mac[:])
	out, _, _, err := m.Match(src[:], dst[:], 12345, 443, consts.IpVersion_4, consts.L4ProtoType_TCP, "", [16]uint8{}, 0, 0, mac16[:])
	if err != nil || out != 2 {
		t.Fatalf("kernel candidate lost possible negative-domain match: %v %v", out, err)
	}
}

func TestDestinationFirstMatchAndTargetSelection(t *testing.T) {
	m, _ := destinationTestMatcher(t, "dip(192.0.2.1) -> dnat(198.51.100.1)\ndip(192.0.2.1) -> dnat(203.0.113.1)\ndip(198.51.100.1) -> dnat(203.0.113.2)")
	targets := []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8::1")}
	m.destination.predicates[0].targets = targets
	p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.8:12345"), Dest: netip.MustParseAddrPort("[::ffff:192.0.2.1]:8443"), routingResult: &bpfRoutingResult{}, networkType: *common.NetworkTCP4.NetworkType()}
	d, err := m.matchDestination(p)
	if err != nil || !d.IsValid() || d.Port() != 8443 || !slices.Contains(targets, d.Addr()) {
		t.Fatalf("bad selected target: %+v %v", d, err)
	}
	p.destination = d
	if p.effectiveDestination() != d {
		t.Fatal("routing must use the rewritten target")
	}
	m.destination.predicates[0].targets = targets[:1]
	d, err = m.matchDestination(p)
	if err != nil || d.Addr() != targets[0] {
		t.Fatalf("recursive rewrite: %+v %v", d, err)
	}
}
