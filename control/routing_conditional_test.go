// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestConditionalUseDiagnostics(t *testing.T) {
	conf := parseStructuredTestConfig(t, `rule_set {
 leaf { dport(443) -> block }
 outer { l4proto(tcp) -> use(leaf) }
}
sip(192.0.2.0/24) -> use(outer)
fallback: direct`)
	m, _ := routingMatcherForTest(t, preparedRules{routing: &conf.Routing})
	for _, tc := range []struct {
		source                  string
		port                    uint16
		missing, needs, skipped bool
	}{
		{"192.0.2.1", 443, false, false, false},
		{"198.51.100.1", 443, false, false, true},
		{"0.0.0.0", 443, true, true, false},
		{"0.0.0.0", 80, true, false, false},
	} {
		_, steps, needs, _, err := m.explainSpans(t.Context(), m.profiles[m.defaultProfileID], routingInput{
			src: netip.AddrPortFrom(netip.MustParseAddr(tc.source), 12345), dst: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), tc.port), l4proto: consts.L4ProtoType_TCP,
		}, map[string]bool{"source_ip": tc.missing}, map[uint8]string{0: "direct", 1: "block"}, "routing")
		if err != nil || (len(needs) != 0) != tc.needs {
			t.Fatalf("%+v: needs=%v err=%v", tc, needs, err)
		}
		for _, step := range steps {
			if step.Outbound == "block" && tc.skipped && (step.Status != "skipped" || step.Reason != "condition_not_matched" || len(step.Conditions) != 0) {
				t.Fatalf("skipped body presented as evaluated: %+v", step)
			}
		}
	}
}

func TestConditionalUseSkipsWholeSharedBody(t *testing.T) {
	var source strings.Builder
	source.WriteString("rule_set { office {\n")
	for i := range 500 {
		fmt.Fprintf(&source, "dport(%d) -> direct(mark:37)\n", 1000+i)
	}
	source.WriteString("} }\nl4proto(tcp) && sip(192.0.2.0/24) -> use(office)\nfallback: direct(mark:11)")
	conf := parseStructuredTestConfig(t, source.String())
	b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source       string
		proto        consts.L4ProtoType
		mark         uint32
		maxEvaluated int
	}{
		{"192.0.2.1", consts.L4ProtoType_TCP, 37, 502},
		{"198.51.100.1", consts.L4ProtoType_TCP, 11, 3},
		{"192.0.2.1", consts.L4ProtoType_UDP, 11, 3},
	} {
		trace := newRoutingExecution()
		got, err := m.evaluateSpans(b.profiles[0].Spans, routingInput{
			src: netip.AddrPortFrom(netip.MustParseAddr(tc.source), 12345), dst: netip.MustParseAddrPort("203.0.113.1:1499"), l4proto: tc.proto, trace: trace,
		})
		if err != nil || got.mark != tc.mark || len(trace.evaluated) > tc.maxEvaluated {
			t.Fatalf("%+v: result=%+v err=%v evaluated=%d", tc, got, err, len(trace.evaluated))
		}
	}
}

// The expanded source is an independent semantic reference. Exercise nested
// and sibling scopes, NOT, noalive and every combination of domain truth values.
func TestConditionalUseThreeValuedScopes(t *testing.T) {
	for not := range 8 {
		conditions := []string{"domain(full:a.example)", "domain(full:b.example)", "domain(full:c.example)"}
		for i := range conditions {
			if not&(1<<i) != 0 {
				conditions[i] = "!" + conditions[i]
			}
		}
		a, b, c := conditions[0], conditions[1], conditions[2]
		texts := []string{
			fmt.Sprintf(`rule_set {
 leaf { dport(80) -> proxy(mark:11,skip_while_noalive)
        dport(443) -> direct(mark:12) }
 nested { %s -> use(leaf)
          dport(8443) -> block(mark:13) }
 sibling { dport(443) -> proxy(mark:14) }
}
%s -> use(nested)
%s -> use(sibling)
fallback: direct(mark:15)`, b, a, c),
			fmt.Sprintf(`%s && %s && dport(80) -> proxy(mark:11,skip_while_noalive)
%s && %s && dport(443) -> direct(mark:12)
%s && dport(8443) -> block(mark:13)
%s && dport(443) -> proxy(mark:14)
fallback: direct(mark:15)`, a, b, a, b, a, c),
		}
		var matchers []*RoutingMatcher
		for _, source := range texts {
			conf := parseStructuredTestConfig(t, source)
			builder, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0, "block": 1, "proxy": 2}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			m, err := builder.BuildUserspace()
			if err != nil {
				t.Fatal(err)
			}
			matchers = append(matchers, m)
		}
		for values := range 27 {
			for _, port := range []uint16{80, 443, 8443, 9000} {
				for _, alive := range []bool{false, true} {
					var results []routingEvaluation
					for _, m := range matchers {
						m.outboundUsable = func(uint8, consts.L4ProtoType, consts.IpVersionType) bool { return alive }
						input := routingInput{src: netip.MustParseAddrPort("192.0.2.1:12345"), dst: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), port), l4proto: consts.L4ProtoType_TCP, kernel: true,
							domainBitmap: make([]uint32, consts.MaxMatchSetLen/32), domainBumpBitmap: make([]uint32, consts.MaxMatchSetLen/32)}
						encoded := values
						for _, name := range []string{"a.example", "b.example", "c.example"} {
							value := encoded % 3
							encoded /= 3
							bits := m.domainMatcher.MatchDomainBitmap(name)
							for i, word := range bits {
								if value == 2 {
									input.domainBitmap[i] |= word
								}
								if value == 1 {
									input.domainBumpBitmap[i] |= word
								}
							}
						}
						result, err := m.evaluateSpans(m.profiles[m.defaultProfileID], input)
						if err != nil {
							t.Fatal(err)
						}
						results = append(results, result)
					}
					if results[0] != results[1] {
						t.Fatalf("not=%d values=%d port=%d alive=%v: conditioned=%+v expanded=%+v", not, values, port, alive, results[0], results[1])
					}
				}
			}
		}
	}
}

func TestRoutingConditionalBlockValidation(t *testing.T) {
	jump := func(distance uint32) bpfMatchSet {
		return bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionConditionalJump), Mark: distance}
	}
	for _, tc := range []struct {
		name  string
		rules []bpfMatchSet
		spans []routingSpan
		valid bool
	}{
		{name: "zero distance", rules: []bpfMatchSet{jump(0), {}}},
		{name: "past program end", rules: []bpfMatchSet{jump(4), {}, {}}},
		{name: "overlapping blocks", rules: []bpfMatchSet{jump(2), jump(2), {}}},
		{name: "inside AND", rules: []bpfMatchSet{jump(2), {Action: uint8(consts.MatchActionAnd), Mark: 2}, {}}},
		{name: "inside OR", rules: []bpfMatchSet{jump(2), {Action: uint8(consts.MatchActionOr), Mark: 1}, {}}},
		{name: "nested shared end", rules: []bpfMatchSet{jump(3), jump(2), {}}, valid: true},
		{name: "nested distinct ends", rules: []bpfMatchSet{jump(4), jump(2), {}, {}}, valid: true},
		{name: "adjacent blocks", rules: []bpfMatchSet{jump(2), {}, jump(2), {}}, valid: true},
		{name: "phase inside block", rules: []bpfMatchSet{jump(2), {}},
			spans: []routingSpan{{End: 1, Phase: routingPhaseIngress}, {Start: 1, End: 2, Phase: routingPhaseFlow}}},
		{name: "phase after block", rules: []bpfMatchSet{jump(2), {}, {}}, valid: true,
			spans: []routingSpan{{End: 2, Phase: routingPhaseIngress}, {Start: 2, End: 3, Phase: routingPhaseFlow}}},
		{name: "reordered shared fragments", rules: []bpfMatchSet{{}, jump(2), {}}, valid: true,
			spans: []routingSpan{{Start: 1, End: 2}, {End: 1}, {Start: 2, End: 3}, {Start: 1, End: 2}, {End: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.spans == nil {
				tc.spans = []routingSpan{{End: uint32(len(tc.rules))}}
			}
			if err := validateRoutingBlocks(tc.rules, tc.spans); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}
