// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/plugin"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// API bypass rules must terminate before either HTTP or destination capture.
// Capture must retain host and port constraints: unrelated direct traffic must
// stay in eBPF even when plugins are enabled. Missing DNS evidence is not a
// reason to divert all TCP or UDP to userspace.
type routingCapture struct {
	http           []plugin.Scope
	requestRouting []plugin.Scope
	controls       []routing.FlowRule
}

// Group positive hosts by their port set, preserving each host/port pairing.
// DNS supplies domain candidates; literal IP scopes need no DNS registration.
// Shared IPs and ordered exclusions are checked again against the actual host
// in userspace. An exclusion in one scope must not erase another scope's allow.
func mitmCapturePredicates(scopes []plugin.Scope) [][]*config_parser.Function {
	type hostGroup struct {
		ports   []uint16
		domains []*config_parser.Param
		ips     []*config_parser.Param
		seen    map[string]bool
	}
	var groups []*hostGroup
	byPorts := make(map[string]*hostGroup)
	for _, scope := range scopes {
		for _, rule := range scope {
			host := strings.TrimSuffix(strings.ToLower(rule.Host), ".")
			if rule.Exclude || host == "" {
				continue
			}
			ports := slices.DeleteFunc(slices.Clone(rule.Ports), func(port uint16) bool { return port == 0 })
			slices.Sort(ports)
			ports = slices.Compact(ports)
			if len(rule.Ports) != 0 && len(ports) == 0 {
				continue // Port zero never matches; do not turn it into all ports.
			}
			key := fmt.Sprint(ports)
			group := byPorts[key]
			if group == nil {
				group = &hostGroup{ports: ports, seen: make(map[string]bool)}
				byPorts[key] = group
				groups = append(groups, group)
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				host = ip.Unmap().String()
				if !group.seen[host] {
					group.ips = append(group.ips, &config_parser.Param{Val: host})
				}
			} else if !group.seen[host] {
				param := &config_parser.Param{Key: "full", Val: host}
				if strings.ContainsAny(host, "*?") {
					pattern := regexp.QuoteMeta(host)
					pattern = strings.ReplaceAll(strings.ReplaceAll(pattern, `\*`, ".*"), `\?`, ".")
					param.Key, param.Val = "regex", "^"+pattern+"$"
				}
				group.domains = append(group.domains, param)
			}
			group.seen[host] = true
		}
	}
	var predicates [][]*config_parser.Function
	for _, group := range groups {
		for _, hosts := range []*config_parser.Function{{Name: "domain", Params: group.domains}, {Name: "dip", Params: group.ips}} {
			if len(hosts.Params) == 0 {
				continue
			}
			predicate := []*config_parser.Function{
				{Name: "l4proto", Params: []*config_parser.Param{{Val: "tcp"}, {Val: "udp"}}}, hosts,
			}
			if len(group.ports) != 0 {
				ports := &config_parser.Function{Name: "dport"}
				for _, port := range group.ports {
					ports.Params = append(ports.Params, &config_parser.Param{Val: strconv.Itoa(int(port))})
				}
				predicate = append(predicate, ports)
			}
			predicates = append(predicates, predicate)
		}
	}
	return predicates
}

// Compile generated capture and flow controls once, before every policy body.
func (b *RoutingMatcherBuilder) addControlPlaneFragment(p *preparedRules) (routingSpan, error) {
	start := uint32(len(b.rules))
	if err := b.rulesBuilder.Apply(p.bypass); err != nil {
		return routingSpan{}, err
	}
	for i := int(start); i < len(b.rules); i++ {
		if b.rules[i].Action == uint8(consts.MatchActionRoute) {
			b.rules[i].Flags |= matchFlagBypass
		}
	}
	applyEffect := func(filter []*config_parser.Function, action consts.MatchAction, flags uint8) error {
		if err := b.rulesBuilder.ApplyPredicate(filter, &routing.Outbound{Name: "direct"}); err != nil {
			return err
		}
		tail := &b.rules[len(b.rules)-1]
		tail.Action = uint8(action)
		tail.Flags |= flags << matchCaptureShift
		return nil
	}
	b.destination.start = len(b.rules)
	for _, rule := range p.destinations {
		// Capture retains the complete predicate, including DNS-backed domains.
		if err := applyEffect(rule.Filter, consts.MatchActionCapture, captureDestination); err != nil {
			return routingSpan{}, fmt.Errorf("destination capture: %w", err)
		}
	}
	if p.capture != nil {
		for _, predicate := range mitmCapturePredicates(p.capture.requestRouting) {
			if err := applyEffect(predicate, consts.MatchActionCapture, captureHTTP|captureHTTPRequest); err != nil {
				return routingSpan{}, fmt.Errorf("HTTP request routing capture: %w", err)
			}
		}
	}
	b.destination.end = len(b.rules)
	b.flow.start = b.destination.end
	if p.capture != nil {
		for _, rule := range p.capture.controls {
			if rule.Action != consts.MatchActionMust && rule.Action != consts.MatchActionBump {
				return routingSpan{}, fmt.Errorf("invalid flow action %d", rule.Action)
			}
			if err := applyEffect(rule.Filter, rule.Action, 0); err != nil {
				return routingSpan{}, fmt.Errorf("flow control: %w", err)
			}
		}
		for _, predicate := range mitmCapturePredicates(p.capture.http) {
			if err := applyEffect(predicate, consts.MatchActionCapture, captureHTTP); err != nil {
				return routingSpan{}, fmt.Errorf("HTTP capture: %w", err)
			}
		}
	}
	if len(b.rules) != b.flow.start {
		b.rules = append(b.rules, bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)})
	}
	b.flow.end = len(b.rules)
	b.routing.start = b.flow.end

	if err := b.rulesBuilder.Apply(p.earlyRoutes); err != nil {
		return routingSpan{}, err
	}
	return routingSpan{Start: start, End: uint32(len(b.rules))}, nil
}

func (b *RoutingMatcherBuilder) addDestinationPredicates(destinations routing.DestinationRewrites) error {
	for _, rule := range destinations {
		entry := destinationPredicate{span: routingSpan{Start: uint32(len(b.rules))}, targets: rule.To, port: rule.Port}
		for _, f := range rule.Filter {
			entry.domain = entry.domain || f.Name == consts.Function_Domain
		}
		if err := b.rulesBuilder.ApplyPredicate(rule.Filter, &routing.Outbound{Name: "direct"}); err != nil {
			return fmt.Errorf("destination predicate: %w", err)
		}
		b.rules[len(b.rules)-1].Action = uint8(consts.MatchActionMatch)
		b.rules = append(b.rules, bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMiss)})
		entry.span.End = uint32(len(b.rules))
		b.destination.predicates = append(b.destination.predicates, entry)
	}
	return nil
}
