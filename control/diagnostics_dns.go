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
	dnsRequest := plugin.DNSRequest{DNSPacket: query.DNSPacket, Network: request.Flow.Protocol, Source: input.src, OriginalDestination: input.dst, Destination: input.dst, Interface: input.ifindex, PolicyKey: plugin.DNSPolicyKey{Generation: c.routingGeneration}}
	identity := routingResult{Pname: input.processName, Ifindex: input.ifindex, ProfileId: input.profileID,
		Physinif: input.physinif, Dscp: input.dscp, Mac: input.mac, CaptureFlags: evaluation.captureFlags}
	(routeDecision{outbound: evaluation.outbound, mark: evaluation.mark, must: evaluation.must}).apply(&identity)
	ctx = context.WithValue(ctx, diagnosticDNSRouteKey{}, identity)
	return plugin.WithDiagnosticDNSRequest(ctx, dnsRequest)
}

// Use the same route-only evaluator as execution, against the sampled matcher.
// A rejected route bypasses caches; incomplete inputs leave the cache unknown.
func diagnosticDNSUpstream(ctx context.Context, state *diagnosticState, query plugin.DNSRequest, dial plugin.DiagnosticDial) (plugin.DNSRequest, bool) {
	identity, known := ctx.Value(diagnosticDNSRouteKey{}).(routingResult)
	ip, err := netip.ParseAddr(dial.Target.IP)
	if !known || err != nil || dial.Target.Port == 0 {
		return query, true
	}
	target := netip.AddrPortFrom(ip, uint16(dial.Target.Port))
	_, decision, err := state.matcher.dnsRoute(ctx, dial.Protocol, target.String(), dial.Target.Domain, &plugin.DNSExchange{DNSRequest: query}, identity)
	if err != nil {
		return query, decision.outbound != consts.OutboundBlock
	}
	query.PolicyKey.Outbound, query.PolicyKey.Mark, query.PolicyKey.Routed = uint8(decision.outbound), decision.mark, true
	query.Network, query.Destination, query.Upstream = dial.Protocol, target, dial.Endpoint
	if query.Upstream == "" {
		query.Upstream = dial.Protocol + "://" + target.String()
	}
	return query, true
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
	return plugin.WithDiagnosticDNSRequest(ctx, plugin.DNSRequest{DNSPacket: plugin.DNSMessage(message)})
}
