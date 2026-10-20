// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

type diagnosticTestPlugin struct {
	explain func(context.Context, api.ExplainRequest) plugin.Explanation
	wrapped bool
}

func (p *diagnosticTestPlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *diagnosticTestPlugin) Explain(ctx context.Context, request api.ExplainRequest) plugin.Explanation {
	return p.explain(ctx, request)
}
func (p *diagnosticTestPlugin) Wrap(_ plugin.Flow, next plugin.Handler) plugin.Handler {
	p.wrapped = true
	return next
}

func TestExplainDNSRewritePreservesCanonicalPacket(t *testing.T) {
	for _, identity := range []plugin.DNSPolicyKey{{}, {Generation: 1}} {
		query := new(dns.Msg).SetQuestion("original.example.", dns.TypeTXT)
		query.Question[0].Qclass = dns.ClassCHAOS
		query.RecursionDesired, query.CheckingDisabled = false, true
		query.SetEdns0(1232, true)
		query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}}}
		original := query.Copy()
		ctx := plugin.WithDiagnosticDNSRequest(t.Context(), plugin.DNSRequest{DNSPacket: plugin.DNSMessage(query), PolicyKey: identity})
		rewrite := &diagnosticTestPlugin{explain: func(ctx context.Context, _ api.ExplainRequest) plugin.Explanation {
			request, _ := plugin.DiagnosticDNSRequest(ctx)
			message := request.MessageCopy()
			message.Question[0].Name = "rewritten.example."
			return plugin.Explanation{Complete: true, DNS: message}
		}}
		visited := false
		inspect := &diagnosticTestPlugin{explain: func(ctx context.Context, _ api.ExplainRequest) plugin.Explanation {
			visited = true
			request, _ := plugin.DiagnosticDNSRequest(ctx)
			expected := original.Copy()
			expected.Question[0].Name = "rewritten.example."
			if !reflect.DeepEqual(request.MessageCopy(), expected) {
				t.Fatalf("packet lost fields: %s", request.MessageCopy())
			}
			if request.PolicyKey.Chain != 7 || request.PolicyKey.Generation != identity.Generation || request.Upstream != "" {
				t.Fatal("plugin namespace or unknown upstream changed")
			}
			return plugin.Explanation{Complete: true}
		}}
		plan := plugin.Plan{DNS: []plugin.DNSScope{{}}}
		host := &Host{dnsChain: 7, instances: []Instance{{ID: "rewrite", Plugin: rewrite, plan: plan}, {ID: "inspect", Plugin: inspect, plan: plan}}}
		// Stale API fields must never reconstruct the downstream query.
		result := host.Explain(ctx, api.ExplainRequest{DNS: &api.DiagnosticDNS{Name: "stale.example.", Type: "A", Class: "IN"}}, true)
		if !result.Complete || !visited {
			t.Fatalf("chain did not reach next plugin: %+v", result)
		}
		request, _ := plugin.DiagnosticDNSRequest(ctx)
		if !reflect.DeepEqual(request.MessageCopy(), original) {
			t.Fatal("explanation mutated caller packet")
		}
	}
}

func TestExplainHTTPScopeMatchesRuntimeChain(t *testing.T) {
	for _, scopes := range [][]plugin.HTTPScope{
		{{Scope: plugin.Scope{{Host: "private.example", Exclude: true}, {Host: "*"}}}},
		{{Scope: plugin.Scope{{Host: "*"}, {Host: "private.example", Exclude: true}}}},
		{{Scope: plugin.Scope{{Host: "*", Exclude: true}}}, {Scope: plugin.Scope{{Host: "private.example", Ports: []uint16{443}}}}},
	} {
		explained := false
		p := &diagnosticTestPlugin{explain: func(context.Context, api.ExplainRequest) plugin.Explanation {
			explained = true
			return plugin.Explanation{Complete: true}
		}}
		host := &Host{instances: []Instance{{ID: "test", Plugin: p, plan: plugin.Plan{Scopes: scopes}}}}
		for _, port := range []uint16{0, 80, 443} {
			p.wrapped, explained = false, false
			host.chain(plugin.Flow{Host: "private.example", Port: port}, func(*plugin.Exchange) (*http.Response, error) { return nil, nil })
			host.Explain(t.Context(), api.ExplainRequest{Flow: api.DiagnosticFlow{Destination: api.DiagnosticTarget{IP: "private.example", Port: int(port)}}}, false)
			if explained != p.wrapped {
				t.Fatalf("scope mismatch at port %d", port)
			}
		}
	}
}
