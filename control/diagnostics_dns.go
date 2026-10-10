// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"cmp"
	"context"
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func (c *ControlPlane) diagnosticDNSContext(ctx context.Context, request api.ExplainRequest, input routingInput, evaluation routingEvaluation, missing map[string]bool, state *diagnosticState) context.Context {
	if request.DNS == nil || evaluation.captureFlags&(captureDestination|captureHTTPRequest) != 0 || state.membershipAssumed {
		return ctx
	}
	for _, name := range []string{"source_ip", "source_port", "mac", "ifindex", "physical_ifindex", "process_name", "dscp", "destination.ip", "destination.port"} {
		if missing[name] {
			return ctx
		}
	}
	identity := routingResult{RouteEpoch: 0, Mark: evaluation.mark, Ifindex: input.ifindex, ProfileId: input.profileID, Mac: input.mac, Outbound: uint8(evaluation.outbound), CaptureFlags: evaluation.captureFlags, Protocol: uint8(input.l4proto), Dscp: input.dscp, Physinif: input.physinif, Generation: c.routingGeneration, Pname: input.processName}
	if evaluation.must {
		identity.Must = 1
	}
	identity.RouteEpoch = state.routeEpoch
	q := request.DNS
	message := new(dns.Msg).SetQuestion(q.Name, dns.StringToType[strings.ToUpper(cmp.Or(q.Type, "A"))])
	message.Question[0].Qclass = dns.StringToClass[strings.ToUpper(cmp.Or(q.Class, "IN"))]
	if q.RD != nil {
		message.RecursionDesired = *q.RD
	}
	message.CheckingDisabled = q.CD
	if q.DO || q.UDPSize != 0 {
		message.SetEdns0(uint16(max(q.UDPSize, 512)), q.DO)
	}
	dnsRequest := plugin.DNSRequest{DNSPacket: plugin.DNSMessage(message), Network: request.Flow.Protocol, Source: input.src, OriginalDestination: input.dst, Destination: input.dst, Interface: input.ifindex, ContextKey: fmt.Sprintf("%s/%s/%+v", input.src, input.dst, identity)}
	return plugin.WithDiagnosticDNSRequest(ctx, dnsRequest)
}
