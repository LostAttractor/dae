// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
	"net/netip"
	"testing"
)

func TestDiagnosticDNSPreservesSourceIdentity(t *testing.T) {
	for _, tc := range []struct {
		origin string
		want   plugin.SourceOrigin
	}{{"lan", plugin.SourceLAN}, {"local", plugin.SourceLocal}, {"daemon", plugin.SourceLocal}, {"", plugin.SourceUnknown}, {"invalid", plugin.SourceUnknown}} {
		t.Run(tc.origin, func(t *testing.T) {
			request := api.ExplainRequest{Context: api.DiagnosticContext{Origin: tc.origin}, Flow: api.DiagnosticFlow{Protocol: "udp"}, DNS: &api.DiagnosticDNS{Name: "example.test", Type: "A"}}
			input := routingInput{src: netip.MustParseAddrPort("[fe80::10%lan]:40000"), dst: netip.MustParseAddrPort("[fe80::1%lan]:53"), ifindex: 2}
			ctx := diagnosticDNSQuestion(t.Context(), request)
			query, ok := plugin.DiagnosticDNSRequest(ctx)
			if !ok || query.SourceOrigin != tc.want {
				t.Fatalf("diagnostic question source = %v, want %v", query.SourceOrigin, tc.want)
			}
			// Transport diagnostics use daemon routing without replacing the original DNS client origin.
			child := request
			child.Context.Origin, child.DNS = "daemon", nil
			ctx = diagnosticDNSQuestion(ctx, child)
			ctx = (&ControlPlane{}).diagnosticDNSContext(ctx, child, input, routingEvaluation{}, nil, &diagnosticState{})
			query, _ = plugin.DiagnosticDNSRequest(ctx)
			if query.SourceOrigin != tc.want {
				t.Fatalf("transport changed source = %v, want %v", query.SourceOrigin, tc.want)
			}
			for _, mac := range [][6]byte{{}, {2, 0, 0, 0, 0, 1}} {
				input.mac = mac
				ctx = (&ControlPlane{}).diagnosticDNSContext(ctx, request, input, routingEvaluation{}, nil, &diagnosticState{})
				query, ok := plugin.DiagnosticDNSRequest(ctx)
				if !ok || query.Source != input.src || query.SourceMAC != mac || query.SourceOrigin != tc.want || query.Interface != input.ifindex {
					t.Fatalf("diagnostic identity lost: %+v", query)
				}
				identity := ctx.Value(diagnosticDNSRouteKey{}).(routingResult)
				if identity.sourceOrigin() != tc.want {
					t.Fatalf("diagnostic routing identity lost: %+v", identity)
				}
			}
		})
	}
}

func TestDiagnosticDNSQuestionWithoutRoutingIdentity(t *testing.T) {
	request := api.ExplainRequest{Kind: "dns", DNS: &api.DiagnosticDNS{Name: "Example.TEST", Type: "txt", Class: "ch", RD: new(false), CD: true, DO: true, UDPSize: 1232}}
	if err := prepareDiagnosticRequest(&request); err != nil {
		t.Fatal(err)
	}
	ctx := diagnosticDNSQuestion(t.Context(), request)
	packet, ok := plugin.DiagnosticDNSRequest(ctx)
	query := packet.MessageCopy()
	if !ok || query == nil || packet.Egress != "" || packet.SourceOrigin != plugin.SourceLAN {
		t.Fatal("known question requires no routing identity")
	}
	if query.Question[0] != (dns.Question{Name: "example.test.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}) || query.RecursionDesired || !query.CheckingDisabled || query.IsEdns0() == nil || !query.IsEdns0().Do() || query.IsEdns0().UDPSize() != 1232 {
		t.Fatalf("lost normalized question fields: %s", query)
	}
}
