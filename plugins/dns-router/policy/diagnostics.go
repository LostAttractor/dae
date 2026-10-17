// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
)

func (m *RequestMatcher) matchValue(i int, qtype uint16, ifindex uint32, dip, sip string, bitmap []uint32) (bool, error) {
	match := &m.matches[i]
	switch match.Type {
	case consts.MatchType_DomainSet:
		return i/32 < len(bitmap) && bitmap[i/32]>>(i%32)&1 != 0, nil
	case consts.MatchType_QType:
		return qtype == match.Value, nil
	case consts.MatchType_IpSet:
		return m.ipSet[match.Value].HasPrefix(dip), nil
	case consts.MatchType_SourceIpSet:
		return m.ipSet[match.Value].HasPrefix(sip), nil
	case consts.MatchType_IfIndex:
		return ifindex != 0 && ifindex == match.Ifindex.Load(), nil
	case consts.MatchType_Fallback:
		return true, nil
	default:
		return false, fmt.Errorf("unknown match type: %v", match.Type)
	}
}

func (m *ResponseMatcher) matchValue(i int, qtype uint16, upstream DnsRequestOutboundIndex, ips []string, bitmap []uint32) (bool, error) {
	match := &m.matches[i]
	switch match.Type {
	case consts.MatchType_DomainSet:
		return i/32 < len(bitmap) && bitmap[i/32]>>(i%32)&1 != 0, nil
	case consts.MatchType_QType:
		return qtype == match.Value, nil
	case consts.MatchType_IpSet:
		return slices.ContainsFunc(ips, m.ipSet[match.Value].HasPrefix), nil
	case consts.MatchType_Upstream:
		return upstream == DnsRequestOutboundIndex(match.Value), nil
	case consts.MatchType_Fallback:
		return true, nil
	default:
		return false, fmt.Errorf("unknown match type: %v", match.Type)
	}
}

type diagnosticAtom struct {
	hit, unknown, not  bool
	action             uint8
	expression, actual string
}

func explainAtoms(ctx context.Context, stage string, atoms []diagnosticAtom, sources map[int]*config_parser.RoutingRule, actionName func(uint8) string) ([]api.ExplainStep, uint8, bool) {
	var steps []api.ExplainStep
	var selected uint8
	terminal, uncertain := false, false
	for start := 0; start < len(atoms); {
		if ctx.Err() != nil {
			return steps, 0, false
		}
		step := api.ExplainStep{ID: fmt.Sprintf("%s/%d", stage, start), Stage: stage, Expression: "fallback", Status: "evaluated", Match: "match", Reason: "predicate_match"}
		if source := sources[start]; source != nil {
			step.Expression = source.String(false, false, true)
			if len(step.Expression) > 2048 {
				step.Expression = source.String(true, false, true)
			}
			for _, origin := range source.Sources {
				step.Sources = append(step.Sources, api.DiagnosticSource{File: origin.File, Line: origin.Line, Column: origin.Column, Expression: origin.Expression})
			}
		}
		miss, unknown := false, false
		i := start
		for {
			hit, unsure := false, false
			for {
				a := atoms[i]
				hit = hit || a.hit && !a.unknown
				unsure = unsure || a.unknown
				if a.action != 0xfe {
					break
				}
				i++
			}
			a := atoms[i]
			unsure = unsure && !hit
			if a.not {
				hit = !hit
			}
			condition := api.ExplainCondition{Expression: a.expression, Actual: a.actual, Expected: a.expression, Match: "miss", Status: "evaluated", Reason: "predicate_miss"}
			if hit {
				condition.Match, condition.Reason = "match", "predicate_match"
			}
			if unsure {
				condition.Match, condition.Reason = "unknown", "missing_context"
			}
			if miss {
				condition.Status = "short_circuit"
			}
			if terminal || uncertain {
				condition.Status = "supplementary"
			}
			miss = miss || !unsure && !hit
			unknown = unknown || unsure
			step.Conditions = append(step.Conditions, condition)
			i++
			if a.action < 0xfe {
				step.Action = actionName(a.action)
				break
			}
		}
		if miss {
			step.Match, step.Reason = "miss", "predicate_miss"
		} else if unknown {
			step.Match, step.Reason = "unknown", "missing_context"
		}
		if terminal {
			step.Status, step.Reason = "not_reached", "earlier_terminal_rule"
		} else if uncertain {
			step.Status = "conditional"
		} else if !miss && unknown {
			uncertain = true
			step.Status = "conditional"
		} else if !miss {
			terminal = true
			selected = atoms[i-1].action
			step.Status = "selected"
		}
		steps = append(steps, step)
		start = i
	}
	return steps, selected, terminal && !uncertain
}

// Explain uses the same predicate functions as RequestSelect/ResponseSelect.
// Reading an upstream's Raw URL never initializes its resolver or transport.
func (s *Dns) Explain(ctx context.Context, input api.ExplainRequest, names []string) plugin.Explanation {
	result := plugin.Explanation{Complete: true}
	if input.DNS == nil {
		result.Complete = false
		return result
	}
	q := input.DNS
	qtype := dnsmessage.StringToType[strings.ToUpper(cmp.Or(q.Type, "A"))]
	sip, sipErr := netip.ParseAddr(input.Context.SourceIP)
	if sipErr != nil {
		sip = netip.IPv4Unspecified()
	}
	dip, dipErr := netip.ParseAddr(input.Flow.Destination.IP)
	if dipErr != nil {
		dip = netip.IPv4Unspecified()
	}
	ifindex := uint32(0)
	if input.Context.IfIndex != nil {
		ifindex = *input.Context.IfIndex
	}
	bitmap := s.reqMatcher.domainMatcher.MatchDomainBitmap(q.Name)
	atoms := make([]diagnosticAtom, len(s.reqMatcher.matches))
	for i := range atoms {
		match := &s.reqMatcher.matches[i]
		hit, err := s.reqMatcher.matchValue(i, qtype, ifindex, addrToBin128(dip), addrToBin128(sip), bitmap)
		a := diagnosticAtom{hit: hit, not: match.Not, action: match.Upstream, expression: fmt.Sprintf("%v(%d)", match.Type, match.Value), actual: q.Name}
		switch match.Type {
		case consts.MatchType_SourceIpSet:
			a.unknown, a.actual = sipErr != nil, input.Context.SourceIP
		case consts.MatchType_IpSet:
			a.unknown, a.actual = dipErr != nil, input.Flow.Destination.IP
		case consts.MatchType_IfIndex:
			a.unknown, a.actual = input.Context.IfIndex == nil, fmt.Sprint(ifindex)
		case consts.MatchType_QType:
			a.actual = cmp.Or(q.Type, "A")
		}
		if err != nil {
			a.unknown = true
		}
		atoms[i] = a
	}
	requestName := func(id uint8) string {
		if int(id) < len(names) {
			return names[id]
		}
		return DnsRequestOutboundIndex(id).String()
	}
	steps, selected, complete := explainAtoms(ctx, "dns_request", atoms, s.reqMatcher.sources, requestName)
	result.Steps = steps
	result.Complete = complete
	if complete && DnsRequestOutboundIndex(selected) == DnsRequestOutboundIndex_Reject {
		result.Terminal = true
		return result
	}
	if complete && int(selected) < len(s.upstream) {
		u := s.upstream[selected].Raw
		result.Steps = append(result.Steps, api.ExplainStep{ID: "upstream", Stage: "dns_upstream", Expression: requestName(selected), Status: "selected", Match: "match", Reason: "configured_upstream", Targets: []string{u.Redacted()}, Action: u.Scheme})
		result.Dials = s.upstream[selected].diagnosticDials(ctx)
	} else if complete && input.Flow.Destination.IP != "" {
		result.Dials = []plugin.DiagnosticDial{{Protocol: cmp.Or(input.Flow.Protocol, "udp"), Target: input.Flow.Destination}}
	}
	responseFrom := DnsRequestOutboundIndex(selected)
	if q.Upstream != "" {
		found := false
		for i, name := range names {
			if name == q.Upstream {
				responseFrom, found = DnsRequestOutboundIndex(i), true
			}
		}
		if !found && q.Upstream == "asis" {
			responseFrom = DnsRequestOutboundIndex_AsIs
		}
	}
	var ips []string
	for _, text := range q.AnswerIPs {
		if ip, err := netip.ParseAddr(text); err == nil {
			ips = append(ips, addrToBin128(ip))
		}
	}
	bitmap = s.respMatcher.domainMatcher.MatchDomainBitmap(q.Name)
	atoms = make([]diagnosticAtom, len(s.respMatcher.matches))
	for i, match := range s.respMatcher.matches {
		hit, err := s.respMatcher.matchValue(i, qtype, responseFrom, ips, bitmap)
		atoms[i] = diagnosticAtom{hit: hit, not: match.Not, action: match.Upstream, expression: fmt.Sprintf("%v(%d)", match.Type, match.Value), actual: fmt.Sprint(q.AnswerIPs), unknown: err != nil || match.Type == consts.MatchType_IpSet && q.RCode == nil && q.AnswerIPs == nil || match.Type == consts.MatchType_Upstream && !complete && q.Upstream == ""}
	}
	responseName := func(id uint8) string {
		if int(id) < len(names) {
			return names[id]
		}
		return DnsResponseOutboundIndex(id).String()
	}
	responseSteps, responseAction, responseComplete := explainAtoms(ctx, "dns_response", atoms, s.respMatcher.sources, responseName)
	result.Steps = append(result.Steps, responseSteps...)
	result.Complete = result.Complete && responseComplete
	if responseComplete && int(responseAction) < len(s.upstream) {
		result.Complete = false
		result.Steps = append(result.Steps, api.ExplainStep{ID: "response_retry", Stage: "dns_response", Expression: responseName(responseAction), Status: "conditional", Match: "unknown", Reason: "retry_response_required", Targets: []string{s.upstream[responseAction].Raw.Redacted()}})
	}
	return result
}

func (u *UpstreamResolver) diagnosticDials(ctx context.Context) []plugin.DiagnosticDial {
	scheme, hostname, port, _, _ := ParseRawUpstream(u.Raw)
	addresses := plugin.SamplesForDiagnostics(ctx).Sample(u, func() []netip.Addr {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.upstream != nil {
			return []netip.Addr{u.upstream.Ip4, u.upstream.Ip6}
		}
		ip, _ := netip.ParseAddr(hostname)
		return []netip.Addr{ip}
	})
	protocols := []string{"tcp"}
	switch scheme {
	case UpstreamScheme_UDP, UpstreamScheme_QUIC, UpstreamScheme_H3:
		protocols = []string{"udp"}
	case UpstreamScheme_TCP_UDP:
		protocols = []string{"udp", "tcp"}
	}
	var targets []plugin.DiagnosticDial
	for _, ip := range addresses {
		if ip.IsValid() {
			for _, proto := range protocols {
				targets = append(targets, plugin.DiagnosticDial{Protocol: proto, Target: api.DiagnosticTarget{IP: ip.String(), Domain: hostname, Port: int(port)}})
			}
		}
	}
	if len(targets) == 0 {
		targets = []plugin.DiagnosticDial{{Protocol: protocols[0], Target: api.DiagnosticTarget{Domain: hostname, Port: int(port)}}}
	}
	return targets
}
