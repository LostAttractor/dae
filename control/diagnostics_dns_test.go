// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
	"testing"
)

func TestDiagnosticDNSQuestionWithoutRoutingIdentity(t *testing.T) {
	request := api.ExplainRequest{Kind: "dns", DNS: &api.DiagnosticDNS{Name: "Example.TEST", Type: "txt", Class: "ch", RD: new(false), CD: true, DO: true, UDPSize: 1232}}
	if err := prepareDiagnosticRequest(&request); err != nil {
		t.Fatal(err)
	}
	ctx := diagnosticDNSQuestion(t.Context(), request)
	packet, ok := plugin.DiagnosticDNSRequest(ctx)
	query := packet.MessageCopy()
	if !ok || query == nil || packet.ContextKey != "" {
		t.Fatal("known question requires no routing identity")
	}
	if query.Question[0] != (dns.Question{Name: "example.test.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}) || query.RecursionDesired || !query.CheckingDisabled || query.IsEdns0() == nil || !query.IsEdns0().Do() || query.IsEdns0().UDPSize() != 1232 {
		t.Fatalf("lost normalized question fields: %s", query)
	}
}
