// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/geodata"
	"google.golang.org/protobuf/proto"
)

func TestConditionalUseMatching(t *testing.T) {
	conf := parseStructuredTestConfig(t, `rule_set {
 first { dport(80,443) -> proxy(mark:11, skip_while_noalive) }
 second { dport(443,853) -> direct(mark:22) }
 nested { !l4proto(udp) && dport(443,853) -> use(first, second) }
 }
 dport(22) -> direct(mark:1)
 sip(192.0.2.0/24) -> use(nested)
 dport(443) -> direct(mark:33)
 fallback: direct(mark:44)`)
	before, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0, "proxy": 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	after, err := conf.Marshal(2)
	if err != nil || !slices.Equal(before, after) {
		t.Fatalf("compilation changed the source configuration: %v", err)
	}
	for _, alive := range []bool{false, true} {
		m.outboundUsable = func(uint8, consts.L4ProtoType, consts.IpVersionType) bool { return alive }
		for _, source := range []string{"192.0.2.1", "198.51.100.1"} {
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				for _, port := range []uint16{22, 80, 443, 853, 9000} {
					wantOutbound, wantMark := consts.OutboundDirect, uint32(44)
					switch {
					case port == 22:
						wantMark = 1
					case source == "192.0.2.1" && proto == consts.L4ProtoType_TCP && (port == 443 || port == 853):
						wantMark = 22
						if port == 443 && alive {
							wantOutbound, wantMark = 2, 11
						}
					case port == 443:
						wantMark = 33
					}
					outbound, mark, must, err := m.match(routingInput{
						src: netip.AddrPortFrom(netip.MustParseAddr(source), 12345),
						dst: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), port), l4proto: proto,
					})
					if err != nil || outbound != wantOutbound || mark != wantMark || must {
						t.Fatalf("source=%s proto=%d port=%d alive=%v: got %d/%d/%v, %v; want %d/%d", source, proto, port, alive, outbound, mark, must, err, wantOutbound, wantMark)
					}
				}
			}
		}
	}
}

func TestConditionalUseSharesOnlyIdenticalConditions(t *testing.T) {
	conf := parseStructuredTestConfig(t, `rule_set { shared { dport(443) -> direct(mark:7) } }
 policy {
  main { sip(192.0.2.0/24) -> use(shared)
   fallback: direct }
  same { sip(192.0.2.0/24) -> use(shared)
   fallback: direct }
  other { sip(198.51.100.0/24) -> use(shared)
   fallback: direct }
  plain { use: shared
   fallback: direct }
 }
 default: main
 interface { lan0: same
 lan1: other
 lan2: plain }`)
	b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Two conditional variants (2 instructions each), an unconditional one,
	// and one shared fallback. Reusing main's condition costs no extra slots.
	if len(b.rules) != 6 || !reflect.DeepEqual(b.profiles[0].Spans, b.profiles[1].Spans) {
		t.Fatalf("condition variants not shared correctly: rules=%d profiles=%+v", len(b.rules), b.profiles)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"main", "same", "other", "plain"} {
		for _, source := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"} {
			want := uint32(0)
			if name == "plain" || name == "other" && source == "198.51.100.1" || (name == "main" || name == "same") && source == "192.0.2.1" {
				want = 7
			}
			_, mark, _, err := m.match(routingInput{
				src: netip.AddrPortFrom(netip.MustParseAddr(source), 12345), dst: netip.MustParseAddrPort("203.0.113.2:443"),
				l4proto: consts.L4ProtoType_TCP, profileID: b.profileIDPlan.ids[name],
			})
			if err != nil || mark != want {
				t.Fatalf("profile=%s source=%s: mark=%d err=%v, want=%d", name, source, mark, err, want)
			}
		}
	}
}

func TestConditionalUseDynamicPredicates(t *testing.T) {
	conf := parseStructuredTestConfig(t, `rule_set { shared { dport(443) -> proxy(mark:7) } }
 client(devices) && interface(lan0) -> use(shared)
 fallback: direct`)
	b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0, "proxy": 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	for _, member := range []bool{true, false, true} {
		var members [][6]byte
		if member {
			members = append(members, mac)
		}
		if err := b.SetClientMembers(m, "devices", members, false); err != nil {
			t.Fatal(err)
		}
		for _, index := range []uint32{7, 9} {
			for _, patch := range b.interfaceRulePatches {
				if err := b.updateIfindex(patch.matchIndex, index, false); err != nil {
					t.Fatal(err)
				}
			}
			outbound, mark, _, err := m.match(routingInput{
				src: netip.MustParseAddrPort("192.0.2.1:12345"), dst: netip.MustParseAddrPort("203.0.113.1:443"),
				l4proto: consts.L4ProtoType_TCP, mac: mac, ifindex: 7,
			})
			want := uint32(0)
			if member && index == 7 {
				want = 7
			}
			if err != nil || mark != want || (outbound == 2) != (want == 7) {
				t.Fatalf("member=%v interface=%d: outbound=%d mark=%d err=%v", member, index, outbound, mark, err)
			}
		}
	}
}

func TestConditionalUseValidatesEmptyAndUnusedFragments(t *testing.T) {
	for _, predicate := range []string{"unknown(value)", "dport(70000)", "client(one,two)", "domain(regex: '(')"} {
		for _, body := range []string{
			`rule_set { empty {} } ` + predicate + ` -> use(empty)`,
			`rule_set { empty {} unused { ` + predicate + ` -> use(empty) } }`,
			`rule_set { empty {} } policy { unused { ` + predicate + ` -> use(empty)` + "\nfallback: direct } }",
			`rule_set { nonempty { dport(443) -> direct } } ` + predicate + ` -> use(nonempty)`,
		} {
			t.Run(body, func(t *testing.T) {
				conf := parseStructuredTestConfig(t, body+"\nfallback: direct")
				b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil)
				if err == nil {
					_, err = b.BuildUserspace()
				}
				if err == nil {
					t.Fatal("accepted invalid use predicate")
				}
			})
		}
	}
	conf := parseStructuredTestConfig(t, `rule_set { empty {} }
 interface(lan0) && client(devices) -> use(empty)
 dport(443) -> direct(mark:7)
 fallback: direct`)
	b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.rules) != 2 || len(b.interfaceRulePatches) != 0 || len(b.ClientSets()) != 0 {
		t.Fatal("empty conditional use published inactive predicates")
	}
}

func TestConditionalUseBoundsEmptyDAGVariants(t *testing.T) {
	var text strings.Builder
	text.WriteString("rule_set { set0 {}\n")
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&text, "set%d { dport(%d) -> use(set%d)\ndport(%d) -> use(set%d) }\n", i, 2*i, i-1, 2*i+1, i-1)
	}
	text.WriteString("}\nuse: set12\nfallback: direct")
	conf := parseStructuredTestConfig(t, text.String())
	_, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "condition variants") {
		t.Fatalf("error = %v, want bounded conditional DAG expansion", err)
	}
}

func TestConditionalUsePreparesGeodataAndAliases(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]proto.Message{
		"geoip.dat":   &geodata.GeoIPList{Entry: []*geodata.GeoIP{{CountryCode: "office", Cidr: []*geodata.CIDR{{Ip: []byte{198, 51, 100, 0}, Prefix: 24}}}}},
		"geosite.dat": &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{CountryCode: "office", Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: "corp.example"}}}}},
	} {
		raw, err := proto.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	conf := parseStructuredTestConfig(t, `rule_set { office { l4proto(tcp) -> direct(mark:7) } }
 ip(geoip:office) && domain(geosite:office) && port(443) -> use(office)
 fallback: direct`)
	p, err := prepareRoutingRules(t.Context(), &conf.Routing, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	// Compilation must consume prepared predicates, without reopening assets.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	b, err := p.compileRouting(map[string]uint8{"direct": 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		dst, domain string
		mark        uint32
	}{
		{"198.51.100.1:443", "corp.example", 7},
		{"198.51.100.1:443", "outside.example", 0},
		{"198.51.100.1:443", "", 0},
		{"203.0.113.1:443", "corp.example", 0},
		{"198.51.100.1:80", "corp.example", 0},
	} {
		_, mark, _, err := m.match(routingInput{
			src: netip.MustParseAddrPort("192.0.2.1:12345"), dst: netip.MustParseAddrPort(test.dst),
			l4proto: consts.L4ProtoType_TCP, domain: test.domain,
		})
		if err != nil || mark != test.mark {
			t.Fatalf("destination=%s domain=%s: mark=%d err=%v, want=%d", test.dst, test.domain, mark, err, test.mark)
		}
	}
}
