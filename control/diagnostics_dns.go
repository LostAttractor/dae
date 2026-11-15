// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net/netip"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

type diagnosticDNSRouteKey struct{}

func (c *ControlPlane) diagnosticDNSContext(ctx context.Context, request api.ExplainRequest, input routingInput, evaluation routingEvaluation, missing map[string]bool, state *diagnosticState) context.Context {
	if request.DNS == nil || evaluation.captureFlags&(captureDestination|captureHTTPRequest) != 0 || state.membershipAssumed {
		return ctx
	}
	for _, name := range []string{"source_ip", "source_port", "mac", "ifindex", "physical_ifindex", "process_name", "dscp", "destination.ip", "destination.port"} {
		if missing[name] {
			return ctx
		}
	}
	query, _ := plugin.DiagnosticDNSRequest(ctx)
	dnsRequest := plugin.DNSRequest{DNSPacket: query.DNSPacket, Network: request.Flow.Protocol, Source: input.src, SourceMAC: input.mac, SourceOrigin: query.SourceOrigin, OriginalDestination: input.dst, Destination: input.dst, Interface: input.ifindex}
	identity := routingResult{Pname: input.processName, Ifindex: input.ifindex, ProfileId: input.profileID,
		Physinif: input.physinif, Dscp: input.dscp, Mac: input.mac, SourceOrigin: uint8(query.SourceOrigin), CaptureFlags: evaluation.captureFlags}
	(routeDecision{outbound: evaluation.outbound, mark: evaluation.mark, must: evaluation.must}).apply(&identity)
	ctx = context.WithValue(ctx, diagnosticDNSRouteKey{}, identity)
	return plugin.WithDiagnosticDNSRequest(ctx, dnsRequest)
}

// Route every transport candidate and select its node with the same evaluator
// as execution, against the sampled state. Blocked candidates never consult
// caches. The cache is known only when every other candidate binds the same
// upstream identity.
func (c *ControlPlane) diagnosticDNSUpstream(ctx context.Context, state *diagnosticState, query plugin.DNSRequest, dials []plugin.DiagnosticDial) (plugin.DNSRequest, bool) {
	identity, known := ctx.Value(diagnosticDNSRouteKey{}).(routingResult)
	if !known {
		return query, true
	}
	var bound *plugin.DNSRequest
	for _, dial := range dials {
		ip, err := netip.ParseAddr(dial.Target.IP)
		if err != nil || dial.Target.Port == 0 {
			return query, true
		}
		target := netip.AddrPortFrom(ip, uint16(dial.Target.Port))
		_, decision, err := state.matcher.dnsRoute(ctx, dial.Protocol, target.String(), dial.Target.Domain, &plugin.DNSExchange{DNSRequest: query}, identity)
		if err != nil {
			if decision.outbound == consts.OutboundBlock {
				continue
			}
			return query, true
		}
		egress, known := c.diagnosticDNSEgress(state, consts.L4ProtoStr(dial.Protocol).ToL4ProtoType(), ip, decision)
		if !known {
			return query, true
		}
		if egress == "" {
			continue // The no-connectivity fallback blocks this candidate.
		}
		candidate := query.WithUpstream(plugin.DNSUpstream{Network: dial.Protocol, Address: target, Hostname: dial.Target.Domain, Endpoint: dial.Endpoint})
		candidate.Egress = egress
		if bound != nil && bound.UpstreamKey() != candidate.UpstreamKey() {
			return query, true
		}
		bound = &candidate
	}
	if bound == nil {
		return query, false
	}
	return *bound, true
}

// diagnosticDNSEgress mirrors selectDialOption on the sampled state. An
// unsampled selection leaves the egress unknown; an empty egress means the
// no-connectivity fallback blocks the dial.
func (c *ControlPlane) diagnosticDNSEgress(state *diagnosticState, proto consts.L4ProtoType, ip netip.Addr, decision routeDecision) (string, bool) {
	index := diagnosticNetworkIndex(proto, consts.IpVersionFromAddr(ip))
	switch outbound := servingOutbound(decision.outbound, *index.NetworkType(), false, c.noConnectivityOutbound, state.matcher.outboundUsable); outbound {
	case consts.OutboundDirect:
		return c.dnsEgress(nil, nil, true, decision.mark), true
	case consts.OutboundBlock:
		return "", true
	default:
		if int(outbound) >= len(c.outbounds) {
			return "", false
		}
		group := c.outbounds[outbound]
		if selected := state.selected[index][uint8(outbound)]; selected != nil || group.SelectsPerConnection() {
			return c.dnsEgress(group, selected, false, decision.mark), true
		}
		return "", false
	}
}

// The API boundary validates and defaults the question before building it once.
func diagnosticDNSQuestion(ctx context.Context, request api.ExplainRequest) context.Context {
	if request.DNS == nil {
		return ctx
	}
	q := request.DNS
	message := new(dns.Msg).SetQuestion(q.Name, dns.StringToType[q.Type])
	message.Question[0].Qclass = dns.StringToClass[q.Class]
	if q.RD != nil {
		message.RecursionDesired = *q.RD
	}
	message.CheckingDisabled = q.CD
	if q.DO || q.UDPSize != 0 {
		message.SetEdns0(uint16(max(q.UDPSize, 512)), q.DO)
	}
	origin := plugin.SourceUnknown
	switch request.Context.Origin {
	case "local", "daemon":
		origin = plugin.SourceLocal
	case "lan":
		origin = plugin.SourceLAN
	}
	return plugin.WithDiagnosticDNSRequest(ctx, plugin.DNSRequest{DNSPacket: plugin.DNSMessage(message), SourceOrigin: origin})
}
