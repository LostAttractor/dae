// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/trie"
)

type diagnosticDomain struct {
	bump, routing []uint32
	resident      bool
}

type diagnosticState struct {
	matcher           *RoutingMatcher
	names             map[uint8]string
	outbounds         map[uint8]api.ExplainOutbound
	usable            map[uint8]bool
	networks          map[common.NetworkIndex]map[uint8]api.ExplainOutbound
	connectivity      map[common.NetworkIndex]map[uint8]bool
	domains           map[netip.Addr]diagnosticDomain
	evidence          []api.DomainEvidence
	registered        map[string]bool
	registeredCount   map[string]int
	registryIPv4      bool
	paired            map[string]map[netip.Addr]bool
	clientSets        map[string]bool
	mitmEnabled       bool
	mitmKnown         bool
	fields            []api.DiagnosticField
	verifiedName      bool
	routeEpoch        uint64
	membershipAssumed bool
}

func diagnosticNetwork(request api.ExplainRequest, destination netip.Addr) (common.NetworkType, error) {
	network := common.NetworkType{L4Proto: consts.L4ProtoStr(request.Flow.Protocol), IpVersion: consts.IpVersionStrFromAddr(destination)}
	if request.Network != "" {
		switch request.Network {
		case "tcp4", "tcp6", "udp4", "udp6":
			network.L4Proto = consts.L4ProtoStr(request.Network[:3])
			network.IpVersion = consts.IpVersionStr(request.Network[3:])
		default:
			return network, fmt.Errorf("network must be tcp4, tcp6, udp4 or udp6")
		}
	}
	return network, nil
}

func (c *ControlPlane) diagnosticState(request api.ExplainRequest, input routingInput, matcher *RoutingMatcher) (*diagnosticState, error) {
	s := &diagnosticState{matcher: matcher, names: make(map[uint8]string), outbounds: make(map[uint8]api.ExplainOutbound), usable: make(map[uint8]bool),
		domains: make(map[netip.Addr]diagnosticDomain), evidence: []api.DomainEvidence{}, registered: make(map[string]bool), paired: make(map[string]map[netip.Addr]bool), clientSets: make(map[string]bool)}
	s.registeredCount, s.registryIPv4 = make(map[string]int), input.dst.Addr().Is4()
	network, err := diagnosticNetwork(request, input.dst.Addr())
	if err != nil {
		return nil, err
	}
	s.networks = make(map[common.NetworkIndex]map[uint8]api.ExplainOutbound)
	s.connectivity = make(map[common.NetworkIndex]map[uint8]bool)
	for index := range common.NetworkIndex(common.NetworkTypeCount) {
		network := index.NetworkType()
		s.networks[index] = make(map[uint8]api.ExplainOutbound)
		s.connectivity[index] = map[uint8]bool{uint8(consts.OutboundDirect): true, uint8(consts.OutboundBlock): true}
		for i, group := range c.outbounds {
			id := uint8(i)
			s.names[id] = group.Name
			s.networks[index][id] = group.ExplainSelection(network)
			s.connectivity[index][id] = s.networks[index][id].Available
			if c.core != nil && id >= uint8(consts.OutboundUserDefinedMin) {
				s.connectivity[index][id] = c.core.outboundUsable(id, network.L4Proto.ToL4ProtoType(), network.IpVersion.ToIpVersionType())
			}
		}
	}
	s.outbounds, s.usable = s.networks[network.Index()], s.connectivity[network.Index()]
	// Tests and no-load configurations may not instantiate builtin groups.
	s.names[uint8(consts.OutboundDirect)], s.names[uint8(consts.OutboundBlock)] = "direct", "block"
	s.usable[uint8(consts.OutboundDirect)], s.usable[uint8(consts.OutboundBlock)] = true, true
	matcher.outboundUsable = func(id uint8, proto consts.L4ProtoType, family consts.IpVersionType) bool {
		return s.connectivity[diagnosticNetworkIndex(proto, family)][id]
	}
	for _, name := range c.clientSets() {
		joined := c.settings != nil && slices.Contains(c.settings.Members(name), input.mac)
		s.clientSets[name] = joined
		s.fields = append(s.fields, api.DiagnosticField{Name: "client." + name, Value: fmt.Sprint(joined), Source: "runtime"})
		if input.mac == [6]byte{} && request.Context.Origin != "daemon" {
			s.fields[len(s.fields)-1].Value, s.fields[len(s.fields)-1].Source = "", "unknown"
		}
	}
	c.muRealDomainSet.Lock()
	if c.realDomainSet != nil {
		s.verifiedName = c.realDomainSet.TestString(diagnosticHostname(request) + ".")
	}
	c.muRealDomainSet.Unlock()
	if c.deviceRoutes != nil {
		c.deviceRoutes.mu.Lock()
		if device := c.deviceRoutes.devices[input.mac]; device != nil {
			s.routeEpoch = device.epoch
		}
		c.deviceRoutes.mu.Unlock()
	}
	if c.settings != nil {
		if enabled, exists := c.settings.MITM(input.mac); exists {
			s.mitmEnabled, s.mitmKnown = enabled, true
		} else if request.Context.SourceIP != "" && request.Context.MAC != "" {
			s.mitmEnabled, _ = c.mitmSelection(input.src.Addr(), input.mac)
			s.mitmKnown = true
		}
	}
	if c.MITMHost() == nil {
		s.mitmKnown = true
	}
	s.fields = append(s.fields, api.DiagnosticField{Name: "mitm.enabled", Value: fmt.Sprint(s.mitmEnabled), Source: "runtime"})
	if !s.mitmKnown {
		s.fields[len(s.fields)-1].Source = "unknown"
	}
	if c.core != nil && c.core.domainRegistry != nil {
		g := c.core.domainRegistry
		g.mu.Lock()
		defer g.mu.Unlock()
		wanted := map[netip.Addr]bool{input.dst.Addr(): true}
		if request.Compare != nil {
			for _, binding := range request.Compare.Bindings {
				ip, _ := diagnosticAddress(binding.IP)
				wanted[ip] = true
			}
		}
		for _, entry := range matcher.destination.predicates {
			for _, ip := range entry.targets {
				wanted[ip.Unmap()] = true
			}
		}
		host := strings.TrimSuffix(strings.ToLower(cmp.Or(request.Flow.Destination.Domain, diagnosticHostname(request))), ".") + "."
		for name, record := range g.byName {
			for ip, pair := range record.addresses {
				if ip.Is4() == input.dst.Addr().Is4() {
					s.registered[name] = true
					s.registeredCount[name]++
				}
				if !wanted[ip] && name != host {
					continue
				}
				if s.paired[name] == nil {
					s.paired[name] = make(map[netip.Addr]bool)
				}
				s.paired[name][ip] = true
				_, resident := g.kernel.resident[ip]
				s.evidence = append(s.evidence, api.DomainEvidence{Domain: name, IP: ip.String(), Resident: resident, RetainUntil: pair.retainUntil, Source: "registry"})
			}
		}
		for ip := range wanted {
			_, resident := g.kernel.resident[ip]
			if record := g.byIP[ip]; record != nil && resident {
				s.domains[ip] = diagnosticDomain{resident: true, bump: slices.Clone(record.bump), routing: slices.Clone(record.routing)}
			}
		}
	}
	slices.SortFunc(s.evidence, func(a, b api.DomainEvidence) int {
		return cmp.Or(strings.Compare(a.Domain, b.Domain), strings.Compare(a.IP, b.IP))
	})
	return s, nil
}

func (s *diagnosticState) assumed(assumptions api.DiagnosticAssumptions, mac [6]byte) (*diagnosticState, error) {
	next := *s
	next.matcher = s.matcher.diagnosticSnapshot()
	next.clientSets, next.usable, next.domains = maps.Clone(s.clientSets), maps.Clone(s.usable), maps.Clone(s.domains)
	next.connectivity = make(map[common.NetworkIndex]map[uint8]bool)
	next.networks = make(map[common.NetworkIndex]map[uint8]api.ExplainOutbound)
	for index, values := range s.networks {
		next.networks[index] = maps.Clone(values)
	}
	next.outbounds = maps.Clone(s.outbounds)
	for index, values := range s.connectivity {
		next.connectivity[index] = maps.Clone(values)
	}
	next.evidence = slices.Clone(s.evidence)
	next.paired = maps.Clone(s.paired)
	next.registered = maps.Clone(s.registered)
	next.registeredCount = maps.Clone(s.registeredCount)
	for name, joined := range assumptions.ClientSets {
		if _, ok := s.clientSets[name]; !ok {
			return nil, fmt.Errorf("unknown client set %q", name)
		}
		if mac == [6]byte{} {
			return nil, fmt.Errorf("client membership comparison requires a MAC")
		}
		next.clientSets[name] = joined
		next.membershipAssumed = next.membershipAssumed || joined != s.clientSets[name]
		for i := range next.matcher.matches {
			if next.matcher.clientAt(uint32(i)) != name {
				continue
			}
			var prefixes []netip.Prefix
			if joined {
				prefixes = sourceMacPrefixes([][6]byte{mac})
			}
			t, err := trie.NewTrieFromPrefixes(prefixes)
			if err != nil {
				return nil, err
			}
			next.matcher.lpmMatcher[next.matcher.clientSlot(uint32(i))] = t
		}
	}
	for name, available := range assumptions.Outbounds {
		found := false
		for id, candidate := range s.names {
			if candidate == name {
				next.usable[id], found = available, true
				for _, values := range next.connectivity {
					values[id] = available
				}
				for _, values := range next.networks {
					value := values[id]
					value.Available = available
					values[id] = value
				}
				value := next.outbounds[id]
				value.Available = available
				next.outbounds[id] = value
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown outbound %q", name)
		}
	}
	next.matcher.outboundUsable = func(id uint8, proto consts.L4ProtoType, family consts.IpVersionType) bool {
		return next.connectivity[diagnosticNetworkIndex(proto, family)][id]
	}
	if assumptions.MITM != nil {
		next.mitmKnown, next.mitmEnabled = true, *assumptions.MITM
	}
	for _, binding := range assumptions.Bindings {
		ip, _ := diagnosticAddress(binding.IP)
		domain := diagnosticDomain{resident: len(binding.Domains) != 0}
		next.evidence = slices.DeleteFunc(next.evidence, func(e api.DomainEvidence) bool { return e.IP == ip.String() })
		for name, pairs := range next.paired {
			if pairs[ip] {
				pairs = maps.Clone(pairs)
				delete(pairs, ip)
				next.paired[name] = pairs
				if ip.Is4() == next.registryIPv4 {
					next.registeredCount[name]--
					next.registered[name] = next.registeredCount[name] > 0
				}
			}
		}
		for i, name := range binding.Domains {
			name = strings.TrimSuffix(strings.ToLower(name), ".") + "."
			bitmap := next.matcher.domainMatcher.MatchDomainBitmap(name)
			if i == 0 {
				domain.bump, domain.routing = slices.Clone(bitmap), slices.Clone(bitmap)
			} else {
				for j, word := range bitmap {
					domain.bump[j] |= word
					domain.routing[j] &= word
				}
			}
			next.evidence = append(next.evidence, api.DomainEvidence{Domain: name, IP: ip.String(), Resident: true, Source: "assumption"})
			pairs := maps.Clone(next.paired[name])
			if pairs == nil {
				pairs = make(map[netip.Addr]bool)
			}
			if !pairs[ip] && ip.Is4() == next.registryIPv4 {
				next.registeredCount[name]++
				next.registered[name] = true
			}
			pairs[ip] = true
			next.paired[name] = pairs
		}
		next.domains[ip] = domain
	}
	return &next, nil
}

// Explain evaluates a pinned control-plane generation. Every comparison uses
// the same copied rule tables, memberships, domain evidence and health samples.
func (c *ControlPlane) Explain(ctx context.Context, request api.ExplainRequest, inherited bool) (*api.ExplainResponse, error) {
	ctx = plugin.WithDiagnosticSamples(ctx)
	if err := prepareDiagnosticRequest(&request); err != nil {
		return nil, err
	}
	if c.routingMatcher == nil {
		return nil, fmt.Errorf("routing is unavailable")
	}
	c.settingsMu.Lock()
	matcher := c.routingMatcher.diagnosticSnapshot()
	input, missing, fields, err := diagnosticInput(request, matcher)
	if err != nil {
		c.settingsMu.Unlock()
		return nil, err
	}
	state, err := c.diagnosticState(request, input, matcher)
	c.settingsMu.Unlock()
	if err != nil {
		return nil, err
	}
	response := &api.ExplainResponse{Schema: api.DiagnosticsSchemaVersion, Generation: c.routingGeneration, ObservedAt: time.Now(), Context: append(fields, state.fields...)}
	if inherited {
		for i := range response.Context {
			field := &response.Context[i]
			if slices.Contains([]string{"source_ip", "mac", "ifindex", "physical_ifindex", "origin"}, field.Name) && field.Source != "unknown" {
				field.Source = "request"
			}
		}
	}
	response.Current, err = c.explainState(ctx, request, state, input, missing)
	if err != nil {
		return nil, err
	}
	if request.Compare != nil {
		next, err := state.assumed(*request.Compare, input.mac)
		if err != nil {
			return nil, err
		}
		compared, err := c.explainState(ctx, request, next, input, missing)
		if err != nil {
			return nil, err
		}
		response.Compared = &compared
		response.Compared.Assumptions = request.Compare
	}
	if request.Kind == "flow" {
		inactive := state.matcher.inactiveSteps(input.profileID, state.names)
		response.Current.Steps = append(response.Current.Steps, inactive...)
		if response.Compared != nil {
			response.Compared.Steps = append(response.Compared.Steps, inactive...)
		}
	}
	if request.Detail == "rules" {
		for i := range response.Current.Steps {
			response.Current.Steps[i].Conditions = nil
		}
		if response.Compared != nil {
			for i := range response.Compared.Steps {
				response.Compared.Steps[i].Conditions = nil
			}
		}
	}
	return response, nil
}

func (c *ControlPlane) explainState(ctx context.Context, request api.ExplainRequest, s *diagnosticState, input routingInput, missing map[string]bool) (api.ExplainResult, error) {
	result := api.ExplainResult{Decision: api.ExplainDecision{Complete: true, Verdict: "analysis", Policy: s.matcher.diagnosticPolicy(input)}, Steps: []api.ExplainStep{}, Domains: slices.Clone(s.evidence), Outbounds: []api.ExplainOutbound{}, Notes: []string{}}
	if request.Kind == "domain" {
		if len(result.Domains) == 0 {
			result.Notes = append(result.Notes, "No retained evidence; no DNS query was sent.")
		}
		return result, nil
	}
	if request.Kind == "outbound" {
		for _, outbound := range s.outbounds {
			if request.Outbound == "" || outbound.Name == request.Outbound {
				result.Outbounds = append(result.Outbounds, outbound)
			}
		}
		if len(result.Outbounds) == 0 {
			return result, fmt.Errorf("outbound not found")
		}
		slices.SortFunc(result.Outbounds, func(a, b api.ExplainOutbound) int { return strings.Compare(a.Name, b.Name) })
		return result, nil
	}
	if request.Kind == "plugins" || request.Kind == "dns" && request.Flow.Destination.IP == "" {
		c.explainPlugins(ctx, request, s, &result, request.Kind == "dns")
		if request.Kind == "dns" {
			result.Notes = append(result.Notes, "DNS policy analysis; provide the DNS server IP and port to include its kernel capture and connection routing.")
		}
		return result, ctx.Err()
	}
	result.Notes = append(result.Notes, "Fresh unfragmented flow at a configured dae hook; existing connection and UDP-source lifetimes may retain a prior decision.")
	ingressDestination := input.dst
	missing = cloneMissing(missing)
	input.domain = "" // A supplied SNI is never kernel DNS evidence.
	if domain := s.domains[input.dst.Addr()]; domain.resident {
		input.domainBitmap, input.domainBumpBitmap = domain.routing, domain.bump
	}
	if missing["destination.ip"] {
		missing["domain_mapping"] = true
	}
	if !input.kernel {
		input.domain = diagnosticHostname(request)
		input.stage = routeAfterTarget
	}
	spans := s.matcher.profiles[input.profileID]
	// Explicit userspace requests choose their destination before routing it.
	// Evaluating the original target here could terminate on a rule that the
	// actual rewritten target never visits.
	evaluation := routingEvaluation{outbound: consts.OutboundDirect}
	var steps []api.ExplainStep
	var required []string
	var selected string
	var err error
	if input.kernel {
		evaluation, steps, required, selected, err = s.matcher.explainSpans(ctx, spans, input, missing, s.names, "kernel")
		if err != nil {
			return result, err
		}
	}
	result.Steps = append(result.Steps, steps...)
	decision := &result.Decision
	decision.RuleID, decision.Mark, decision.Must, decision.Capture = selected, evaluation.mark, evaluation.must, captureNames(evaluation.captureFlags)
	decision.OriginalTarget = input.dst.String()
	decision.Targets = []string{input.dst.String()}
	decision.Outbound = s.names[uint8(evaluation.outbound)]
	decision.Verdict = "userspace"
	if input.kernel && evaluation.outbound == consts.OutboundDirect && evaluation.captureFlags == 0 {
		decision.Verdict = "kernel_direct"
	}
	if evaluation.outbound == consts.OutboundBlock {
		decision.Verdict = "drop"
	}
	for _, field := range []string{"destination.ip", "destination.port"} {
		if missing[field] {
			required = append(required, field)
		}
	}
	if missing["ifindex"] && request.Context.Policy == "" && len(s.matcher.profileInfo) > 1 {
		required = append(required, "ifindex")
	}
	if len(required) != 0 {
		decision.Complete, decision.Verdict, decision.Outbound, decision.RuleID = false, "unknown", "", ""
		slices.Sort(required)
		decision.Missing = slices.Compact(required)
		if missing["destination.ip"] {
			decision.OriginalTarget = net.JoinHostPort(request.Flow.Destination.Domain, fmt.Sprint(request.Flow.Destination.Port))
			decision.Targets = nil
			for _, evidence := range s.evidence {
				if strings.EqualFold(strings.TrimSuffix(evidence.Domain, "."), strings.TrimSuffix(request.Flow.Destination.Domain, ".")) {
					decision.Targets = append(decision.Targets, net.JoinHostPort(evidence.IP, fmt.Sprint(request.Flow.Destination.Port)))
				}
			}
		}
		return result, nil
	}
	if decision.Verdict == "kernel_direct" || decision.Verdict == "drop" {
		return result, nil
	}
	// The classifier rejects unavailable ordinary proxies immediately when
	// configured to block. Capture and DNS run their own userspace decisions.
	if input.kernel && input.dst.Port() != 53 && evaluation.captureFlags == 0 && evaluation.outbound >= consts.OutboundUserDefinedMin && evaluation.outbound < consts.OutboundMustRules && !s.usable[uint8(evaluation.outbound)] && c.noConnectivityOutbound == consts.OutboundBlock && !c.noConnectivityTrySniff {
		decision.Verdict = "drop"
		result.Notes = append(result.Notes, "No available outbound; kernel no-connectivity policy blocks this flow.")
		return result, nil
	}
	if request.Kind == "dns" || evaluation.captureFlags&8 != 0 {
		if evaluation.must {
			result.Notes = append(result.Notes, "must bypasses DNS middleware.")
		} else {
			if c.explainPlugins(c.diagnosticDNSContext(ctx, request, input, evaluation, missing, s), request, s, &result, true) {
				return result, ctx.Err()
			}
		}
		if !decision.Complete || decision.Verdict == "local_response" {
			return result, ctx.Err()
		}
	}
	hostname := diagnosticHostname(request)
	noSniff := input.kernel && input.dst.Port() != 53 && evaluation.captureFlags == 0 && evaluation.outbound >= consts.OutboundUserDefinedMin && evaluation.outbound < consts.OutboundMustRules && !s.usable[uint8(evaluation.outbound)] && !c.noConnectivityTrySniff
	if noSniff {
		hostname = ""
		delete(missing, "hostname")
		result.Notes = append(result.Notes, "Kernel no-connectivity handoff disables sniffing for this flow.")
	}
	if evaluation.captureFlags&captureHTTP != 0 {
		c.explainPlugins(ctx, request, s, &result, false)
		if !decision.Complete || decision.Verdict == "local_response" {
			return result, ctx.Err()
		}
	}
	targetRoute := evaluation.captureFlags&(captureDestination|captureHTTPRequest) != 0 || !input.kernel
	if targetRoute {
		for i, entry := range s.matcher.destination.predicates {
			p := input
			p.kernel, p.domain, p.domainBitmap, p.domainBumpBitmap, p.stage = false, hostname, nil, nil, routeFromIngress
			matched, trace, needs, _, err := s.matcher.explainSpans(ctx, []routingSpan{entry.span}, p, missing, s.names, fmt.Sprintf("destination/%d", i))
			if err != nil {
				return result, err
			}
			for j := range trace {
				for _, ip := range entry.targets {
					port := entry.port
					if port == 0 {
						port = p.dst.Port()
					}
					trace[j].Targets = append(trace[j].Targets, netip.AddrPortFrom(ip, port).String())
				}
			}
			result.Steps = append(result.Steps, trace...)
			if len(needs) != 0 {
				decision.Complete, decision.Missing = false, needs
				return result, nil
			}
			if entry.domain && hostname == "" || !matched.matched {
				continue
			}
			decision.Targets = nil
			for _, ip := range entry.targets {
				port := entry.port
				if port == 0 {
					port = input.dst.Port()
				}
				decision.Targets = append(decision.Targets, netip.AddrPortFrom(ip, port).String())
			}
			if len(entry.targets) != 1 {
				decision.Complete, decision.Outbound = false, ""
				result.Notes = append(result.Notes, "Random destination candidates are listed; no target was selected.")
				return result, nil
			}
			input.dst = netip.MustParseAddrPort(decision.Targets[0])
			break
		}
	}
	valid := evaluation.outbound < consts.OutboundMustRules
	reroute := targetRoute || !valid || c.rerouteMode == consts.RerouteMode_Force
	preservesKernel := evaluation.captureFlags != 0 && valid && !targetRoute && evaluation.outbound == consts.OutboundDirect
	if input.kernel && missing["hostname"] && !noSniff && !preservesKernel && (c.rerouteMode != consts.RerouteMode_None || c.dialTargetOverride || !valid) {
		decision.Complete, decision.Outbound = false, ""
		decision.Missing = append(decision.Missing, "hostname")
		result.Notes = append(result.Notes, "Sniff-dependent routing requires an explicit SNI/HTTP context; an empty SNI declares its absence.")
		return result, nil
	}
	verified, verificationKnown := hostname != "" && c.sniffVerifyMode == consts.SniffVerifyMode_None, true
	key := hostname + "."
	if hostname != "" && c.sniffVerifyMode != consts.SniffVerifyMode_None {
		verified = s.registered[key] && (c.sniffVerifyMode == consts.SniffVerifyMode_Loose || s.paired[key][ingressDestination.Addr()])
		if c.sniffVerifyMode == consts.SniffVerifyMode_Loose && !s.registered[key] {
			verified, verificationKnown = s.verifiedName, s.verifiedName
		}
	}
	if request.Context.Origin == "daemon" {
		verified, verificationKnown = hostname != "", true
	}
	covered := s.paired[key][ingressDestination.Addr()] && (s.domains[ingressDestination.Addr()].resident || domainBitmapAllZero(s.matcher.domainMatcher.MatchDomainBitmap(hostname)))
	if c.rerouteMode == consts.RerouteMode_WhileNeed && hostname != "" && !covered {
		reroute = true
	}
	if evaluation.captureFlags != 0 && valid && !targetRoute && (evaluation.outbound == consts.OutboundDirect || evaluation.outbound == consts.OutboundBlock) {
		reroute = false
	}
	if reroute {
		if !verificationKnown {
			decision.Complete, decision.Outbound = false, ""
			decision.Missing = []string{"hostname_verification"}
			result.Notes = append(result.Notes, "Loose hostname verification needs resolver evidence; diagnostics does not query DNS.")
			return result, nil
		}
		if !verified && evaluation.captureFlags != 0 && !targetRoute {
			decision.Complete, decision.Outbound = false, ""
			decision.Missing = []string{"trusted_hostname"}
			return result, nil
		}
		input.kernel, input.domainBitmap, input.domainBumpBitmap = false, nil, nil
		if verified || request.Context.Origin == "daemon" {
			input.domain = hostname
		} else {
			input.domain = ""
		}
		if targetRoute {
			input.stage = routeAfterTarget
			if input.domain == "" {
				domain := s.domains[input.dst.Addr()]
				input.domainBitmap, input.domainBumpBitmap = domain.routing, domain.bump
			}
		}
		var needs []string
		evaluation, steps, needs, selected, err = s.matcher.explainSpans(ctx, spans, input, missing, s.names, "userspace")
		if err != nil {
			return result, err
		}
		result.Steps = append(result.Steps, steps...)
		decision.RuleID, decision.Mark, decision.Must = selected, evaluation.mark, evaluation.must
		decision.Outbound = s.names[uint8(evaluation.outbound)]
		if len(needs) != 0 || evaluation.outbound >= consts.OutboundMustRules {
			decision.Complete, decision.Outbound = false, ""
			decision.Missing = append(needs, "trusted_hostname")
			return result, nil
		}
	}
	if evaluation.outbound == consts.OutboundBlock {
		decision.Verdict = "drop"
		return result, nil
	}
	if c.dialTargetOverride && verified && input.l4proto == consts.L4ProtoType_TCP && !targetRoute {
		decision.Targets = []string{net.JoinHostPort(hostname, fmt.Sprint(input.dst.Port()))}
		if host := c.MITMHost(); host != nil && host.UseDNSAddress(hostname, evaluation.outbound != consts.OutboundDirect) {
			decision.Targets = []string{input.dst.String()}
		}
	}
	networkIndex := diagnosticNetworkIndex(input.l4proto, consts.IpVersionFromAddr(input.dst.Addr()))
	if outbound, exists := s.networks[networkIndex][uint8(evaluation.outbound)]; exists {
		result.Outbounds = append(result.Outbounds, outbound)
		if !outbound.Available && evaluation.outbound >= consts.OutboundUserDefinedMin {
			decision.OriginalOutbound, decision.Outbound = decision.Outbound, s.names[uint8(c.noConnectivityOutbound)]
			result.Notes = append(result.Notes, "No usable node in the sampled state; automatic recovery can change the next connection's choice.")
			if c.noConnectivityOutbound == consts.OutboundBlock {
				decision.Verdict = "drop"
			}
		}
	}
	return result, ctx.Err()
}

func (c *ControlPlane) explainPlugins(ctx context.Context, request api.ExplainRequest, state *diagnosticState, result *api.ExplainResult, dns bool) bool {
	host := c.MITMHost()
	if host == nil {
		result.Steps = append(result.Steps, api.ExplainStep{ID: "plugins/disabled", Stage: "configuration", Expression: "plugin host", Status: "inactive", Match: "miss", Reason: "no_active_plugins"})
		return false
	}
	if !dns && !state.mitmKnown {
		result.Decision.Complete = false
		result.Decision.Missing = append(result.Decision.Missing, "mitm_client_identity")
		return false
	}
	if !dns && !state.mitmEnabled {
		result.Steps = append(result.Steps, api.ExplainStep{ID: "mitm/client", Stage: "mitm", Expression: "device MITM gate", Status: "skipped", Match: "miss", Reason: "client_not_allowed"})
		return false
	}
	if !dns && request.Flow.SNI == nil && request.Flow.HTTP == nil {
		result.Decision.Complete = false
		result.Decision.Missing = append(result.Decision.Missing, "hostname")
		return false
	}
	output := host.Explain(ctx, request, dns)
	result.Steps = append(result.Steps, output.Steps...)
	if !output.Complete {
		result.Decision.Complete = false
		result.Decision.Outbound = ""
		result.Notes = append(result.Notes, "A plugin requires runtime execution or additional context; subsequent routing is undetermined.")
	}
	if output.HTTP != nil && request.Flow.HTTP != nil && output.HTTP.URL != request.Flow.HTTP.URL {
		result.Decision.Complete, result.Decision.Outbound = false, ""
		result.Decision.Targets = []string{output.HTTP.URL}
		result.Decision.Missing = append(result.Decision.Missing, "rewritten_target_address")
	}
	if output.Terminal {
		result.Decision.Complete = output.Complete
		result.Decision.Outbound = ""
		result.Decision.Targets = nil
		result.Decision.Verdict = "local_response"
	}
	if len(output.Dials) != 0 {
		result.Decision.Targets = nil
		result.Decision.Outbound = ""
		for i, dial := range output.Dials {
			target := net.JoinHostPort(cmp.Or(dial.Target.IP, dial.Target.Domain), fmt.Sprint(dial.Target.Port))
			result.Decision.Targets = append(result.Decision.Targets, target)
			child := request
			child.Kind, child.DNS, child.Compare = "flow", nil, nil
			child.Context.Origin = "daemon"
			child.Flow = api.DiagnosticFlow{Protocol: dial.Protocol, Destination: dial.Target}
			input, missing, _, err := diagnosticInput(child, state.matcher)
			if err != nil {
				result.Decision.Complete = false
				result.Notes = append(result.Notes, err.Error())
				continue
			}
			_, inheritedMissing, _, err := diagnosticInput(request, state.matcher)
			if err != nil {
				result.Decision.Complete = false
				result.Notes = append(result.Notes, err.Error())
				continue
			}
			for _, field := range []string{"source_ip", "source_port", "mac", "ifindex", "physical_ifindex", "process_name", "dscp"} {
				if inheritedMissing[field] {
					missing[field] = true
				}
			}
			transport, err := c.explainState(ctx, child, state, input, missing)
			if err != nil {
				result.Decision.Complete = false
				result.Notes = append(result.Notes, err.Error())
				continue
			}
			for _, step := range transport.Steps {
				step.ID = fmt.Sprintf("dns_transport/%d/%s", i, step.ID)
				step.Parent = target
				result.Steps = append(result.Steps, step)
			}
			result.Outbounds = append(result.Outbounds, transport.Outbounds...)
			result.Decision.Complete = result.Decision.Complete && transport.Decision.Complete
			result.Decision.Missing = append(result.Decision.Missing, transport.Decision.Missing...)
			if len(output.Dials) == 1 {
				result.Decision.Outbound, result.Decision.OriginalOutbound = transport.Decision.Outbound, transport.Decision.OriginalOutbound
				result.Decision.Mark, result.Decision.Must = transport.Decision.Mark, transport.Decision.Must
				result.Decision.Targets = transport.Decision.Targets
				result.Decision.Verdict = transport.Decision.Verdict
			}
		}
		if len(output.Dials) > 1 {
			result.Decision.Complete = false
			result.Notes = append(result.Notes, "DNS transport candidates are analyzed independently; no protocol/address race was executed.")
		}
	}
	return len(output.Dials) != 0 || output.Terminal
}
