// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
)

type routingExecution struct {
	visited, evaluated, noalive map[routingTracePosition]bool
	last                        routingTracePosition
}

type routingTracePosition struct {
	span        int
	instruction uint32
}

func newRoutingExecution() *routingExecution {
	return &routingExecution{visited: make(map[routingTracePosition]bool), evaluated: make(map[routingTracePosition]bool), noalive: make(map[routingTracePosition]bool)}
}

// Capture mutable instruction/interface bindings and dynamic tries together.
// Published tries and source metadata are immutable; membership replaces tries.
func (m *RoutingMatcher) diagnosticSnapshot() *RoutingMatcher {
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	copy := *m
	copy.matches = slices.Clone(m.matches)
	copy.lpmMatcher = slices.Clone(m.lpmMatcher)
	copy.rulesMu = new(sync.RWMutex)
	return &copy
}

func diagnosticAction(action uint8) string {
	switch consts.MatchAction(action) {
	case consts.MatchActionRoute:
		return "route"
	case consts.MatchActionMust:
		return "must"
	case consts.MatchActionBump:
		return "bump"
	case consts.MatchActionCapture:
		return "capture"
	case consts.MatchActionFlowEnd:
		return "flow_end"
	case consts.MatchActionMatch:
		return "destination"
	case consts.MatchActionMiss:
		return "destination_miss"
	}
	return "logical"
}

func diagnosticMatch(value predicateResult) string {
	switch value {
	case predicateMatch:
		return "match"
	case predicateUnknown:
		return "ambiguous"
	default:
		return "miss"
	}
}

func captureNames(flags uint8) []string {
	var names []string
	for _, bit := range []struct {
		mask uint8
		name string
	}{{captureHTTP, "http"}, {captureDestination, "destination"}, {captureHTTPRequest, "http_request"}, {8, "dns"}} {
		if flags&bit.mask != 0 {
			names = append(names, bit.name)
		}
	}
	return names
}

func profileName(profile routingProfile) string {
	if profile.Name == "" {
		return "default"
	}
	return profile.Name
}

func (m *RoutingMatcher) diagnosticPolicy(input routingInput) string {
	for _, profile := range m.profileInfo {
		if profile.ID == input.profileID || input.profileID == 0 && profile.ID == m.defaultProfileID {
			return profileName(profile)
		}
	}
	return "default"
}

// unknownFields is diagnostic uncertainty, distinct from the kernel's MAYBE
// (shared-IP ambiguity). A known empty domain bitmap is a definite kernel miss.
func diagnosticField(kind consts.MatchType, input routingInput, metadata routingMatchMetadata) (field, actual string) {
	switch kind {
	case consts.MatchType_SourceIpSet:
		return "source_ip", input.src.Addr().String()
	case consts.MatchType_IpSet:
		return "destination.ip", input.dst.Addr().String()
	case consts.MatchType_Port:
		return "destination.port", strconv.Itoa(int(input.dst.Port()))
	case consts.MatchType_SourcePort:
		return "source_port", strconv.Itoa(int(input.src.Port()))
	case consts.MatchType_Mac:
		return "mac", net.HardwareAddr(input.mac[:]).String()
	case consts.MatchType_ProcessName:
		return "process_name", strings.TrimRight(string(input.processName[:]), "\x00")
	case consts.MatchType_IfIndex:
		return "ifindex", fmt.Sprintf("ifindex=%d physical_ifindex=%d", input.ifindex, input.physinif)
	case consts.MatchType_Dscp:
		return "dscp", strconv.Itoa(int(input.dscp))
	case consts.MatchType_DomainSet:
		if input.kernel {
			return "domain_mapping", "current kernel DNS-IP evidence"
		}
		return "hostname", input.domain
	case consts.MatchType_IpVersion:
		return "destination.ip", input.dst.Addr().String()
	case consts.MatchType_L4Proto:
		return "protocol", fmt.Sprint(input.l4proto)
	}
	return "", "always"
}

type diagnosticClause struct {
	condition api.ExplainCondition
	value     predicateResult
	unknown   bool
	missing   []string
}

func (m *RoutingMatcher) explainClause(predicates *routingPredicates, spanIndex int, start, end uint32, execution *routingExecution, missing map[string]bool) (diagnosticClause, error) {
	clause := diagnosticClause{condition: api.ExplainCondition{Status: "supplementary"}}
	var actual []string
	for i := start; i <= end; i++ {
		match := &m.matches[i]
		metadata := m.matchMetadata[i]
		field, value := diagnosticField(consts.MatchType(match.Type), predicates.input, metadata)
		fieldUnknown := missing[field]
		if consts.MatchType(match.Type) == consts.MatchType_IfIndex {
			index := binary.LittleEndian.Uint32(match.Value[:])
			knownHit := index != 0 && (!missing["ifindex"] && predicates.input.ifindex == index || !missing["physical_ifindex"] && predicates.input.physinif == index)
			fieldUnknown = (missing["ifindex"] || missing["physical_ifindex"]) && index != 0 && !knownHit
			if fieldUnknown && !missing["ifindex"] {
				field = "physical_ifindex"
			}
		}
		if i == start {
			clause.condition.Expression = metadata.expression
			clause.condition.Expected = metadata.expression
		}
		if fieldUnknown {
			clause.unknown = true
			clause.missing = append(clause.missing, field)
			actual = append(actual, field+" is unknown")
			continue
		}
		result, err := predicates.match(m, match)
		if err != nil {
			return clause, err
		}
		clause.value = max(clause.value, result)
		if consts.MatchType(match.Type) == consts.MatchType_DomainSet && predicates.input.kernel {
			value += ": " + diagnosticMatch(result)
			if predicates.input.domainBitmap == nil {
				value = "no resident domain-IP mapping"
			}
		}
		actual = append(actual, value)
	}
	if clause.value == predicateMatch {
		clause.unknown = false // A known OR hit decides the entire clause.
		clause.missing = nil
	}
	if m.matches[end].Flags&matchFlagNot != 0 {
		clause.value = predicateMatch - clause.value
	}
	clause.condition.Match = diagnosticMatch(clause.value)
	clause.condition.Reason = "predicate_" + clause.condition.Match
	if clause.unknown {
		clause.condition.Match, clause.condition.Reason = "unknown", "missing_context"
	}
	if execution != nil {
		for i := start; i <= end; i++ {
			if execution.evaluated[routingTracePosition{spanIndex, i}] {
				clause.condition.Status = "evaluated"
				break
			}
			if execution.visited[routingTracePosition{spanIndex, i}] {
				clause.condition.Status = "short_circuit"
			}
		}
	}
	slices.Sort(actual)
	clause.condition.Actual = strings.Join(slices.Compact(actual), "; ")
	if clause.condition.Expression == "" {
		clause.condition.Expression, clause.condition.Expected = "fallback", "always"
	}
	return clause, nil
}

// explainSpans executes the production interpreter, then supplements its
// short-circuited predicates with independent analysis on the same snapshot.
// Supplemental results never feed back into the production decision.
func (m *RoutingMatcher) explainSpans(ctx context.Context, spans []routingSpan, input routingInput, missing map[string]bool, names map[uint8]string, stage string) (routingEvaluation, []api.ExplainStep, []string, string, error) {
	execution := newRoutingExecution()
	input.trace = execution
	result, err := m.evaluateSpans(spans, input)
	if err != nil {
		return result, nil, nil, "", err
	}
	predicates := routingPredicates{input: input, ipVersion: consts.IpVersionFromAddr(input.dst.Addr())}
	steps := make([]api.ExplainStep, 0)
	var required []string
	uncertain := false
	selectedID := ""
	occurrence := 0
	for spanIndex, span := range spans {
		start := span.Start
		if input.stage == routeAfterTarget {
			start = max(start, uint32(m.flow.start))
		}
		for start < span.End {
			if err := ctx.Err(); err != nil {
				return result, nil, nil, "", err
			}
			end := start
			for end < span.End && (m.matches[end].Action == uint8(consts.MatchActionOr) || m.matches[end].Action == uint8(consts.MatchActionAnd)) {
				end++
			}
			if end >= span.End {
				return result, nil, nil, "", fmt.Errorf("unterminated diagnostic rule")
			}
			metadata := m.ruleMetadata[start]
			tail := m.matches[end]
			step := api.ExplainStep{ID: fmt.Sprintf("%s/%d/%d", stage, occurrence, start), Parent: m.diagnosticPolicy(input), Stage: stage,
				Expression: metadata.expression, Sources: metadata.sources, Action: diagnosticAction(tail.Action), Status: "not_reached", Match: "match", Reason: "earlier_terminal_rule"}
			occurrence++
			if metadata.owner != "" && metadata.owner != step.Parent {
				step.Parent += "/" + metadata.owner
			}
			if tail.Action == uint8(consts.MatchActionRoute) {
				step.Outbound, step.Mark, step.Must = names[tail.Outbound], tail.Mark, tail.Flags&matchFlagMust != 0
			}
			if step.Expression == "" {
				step.Expression = step.Action
			}
			visited := false
			var ruleMissing []string
			knownMiss, ambiguous, unknown := false, false, false
			for clauseStart := start; clauseStart <= end; {
				clauseEnd := clauseStart
				for clauseEnd < end && m.matches[clauseEnd].Action == uint8(consts.MatchActionOr) {
					clauseEnd++
				}
				clause, err := m.explainClause(&predicates, spanIndex, clauseStart, clauseEnd, execution, missing)
				if err != nil {
					return result, nil, nil, "", err
				}
				if knownMiss && clause.condition.Status == "supplementary" {
					clause.condition.Status = "short_circuit"
				}
				step.Conditions = append(step.Conditions, clause.condition)
				unknown = unknown || clause.unknown
				knownMiss = knownMiss || !clause.unknown && clause.value == predicateMiss
				ambiguous = ambiguous || clause.value == predicateUnknown
				ruleMissing = append(ruleMissing, clause.missing...)
				for i := clauseStart; i <= clauseEnd; i++ {
					visited = visited || execution.visited[routingTracePosition{spanIndex, i}]
				}
				clauseStart = clauseEnd + 1
			}
			switch {
			case knownMiss:
				step.Match = "miss"
			case unknown:
				step.Match = "unknown"
			case ambiguous:
				step.Match = "ambiguous"
			}
			if visited {
				step.Status, step.Reason = "evaluated", "predicate_"+step.Match
				if execution.noalive[routingTracePosition{spanIndex, end}] {
					step.Status, step.Reason = "skipped", "outbound_unavailable"
				} else if execution.last == (routingTracePosition{spanIndex, end}) && step.Match != "miss" {
					step.Status, step.Reason = "selected", "terminal_decision"
					selectedID = step.ID
				}
			}
			if (visited || uncertain) && !knownMiss && unknown {
				if tail.Flags&matchFlagSkipNoalive != 0 && m.outboundUsable != nil && !m.outboundUsable(tail.Outbound, input.l4proto, predicates.ipVersion) {
					unknown = false
					step.Status, step.Reason = "skipped", "outbound_unavailable"
				}
			}
			if (visited || uncertain) && !knownMiss && unknown {
				required = append(required, ruleMissing...)
				uncertain = true
			}
			if uncertain {
				step.Status, step.Reason = "conditional", "missing_context"
			}
			steps = append(steps, step)
			start = end + 1
		}
	}
	slices.Sort(required)
	return result, steps, slices.Compact(required), selectedID, nil
}

func cloneMissing(missing map[string]bool) map[string]bool { return maps.Clone(missing) }

// Interface predicates encode dynamic ifindices. This lookup uses their exact
// published values; it never guesses a physical ingress from an IP route.
func (m *RoutingMatcher) profileForInterface(index uint32) uint32 {
	for _, profile := range m.profileInfo {
		for _, name := range profile.InterfaceNames {
			iface, err := net.InterfaceByName(name)
			if err == nil && uint32(iface.Index) == index {
				return profile.ID
			}
		}
	}
	return m.defaultProfileID
}

func diagnosticMAC(text string) ([6]byte, error) {
	parsed, err := net.ParseMAC(text)
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 || [6]byte(parsed) == [6]byte{} {
		return [6]byte{}, fmt.Errorf("expected a nonzero unicast Ethernet MAC")
	}
	return [6]byte(parsed), nil
}

func diagnosticAddress(text string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(text)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("expected an unzoned IP address: %q", text)
	}
	return ip.Unmap(), nil
}

func (m *RoutingMatcher) clientAt(index uint32) string {
	if meta := m.matchMetadata[index]; meta.client != "" {
		return meta.client
	}
	return ""
}

func (m *RoutingMatcher) clientSlot(index uint32) int {
	return int(binary.LittleEndian.Uint32(m.matches[index].Value[:]))
}
