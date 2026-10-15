// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
	cache "github.com/daeuniverse/dae/plugins/dns-cache"
	dns "github.com/miekg/dns"
)

func TestCacheIsolatesReloadedDNSPolicy(t *testing.T) {
	services := plugin.Services{BaseDir: t.TempDir()}
	load := func(previous *mitm.Host, ip string) (*mitm.Host, *pluginhost.Configuration) {
		t.Helper()
		address := exchangeServer(t, "udp", func(query *dns.Msg) *dns.Msg {
			response := new(dns.Msg).SetReply(query)
			rr, err := dns.NewRR(query.Question[0].Name + " 60 IN A " + ip)
			if err != nil {
				t.Error(err)
			}
			response.Answer = []dns.RR{rr}
			return response
		})
		sections, err := config_parser.Parse(fmt.Sprintf(`cache {} router { upstream { test:'udp://%s' } routing { request { fallback:test } } }`, address))
		if err != nil {
			t.Fatal(err)
		}
		configuration, err := pluginhost.Configure(map[string]plugin.Definition{"cache": cache.Plugin, "router": Plugin}, []plugin.Spec{
			{ID: "cache", Type: "cache", Config: sections[0]},
			{ID: "router", Type: "router", Config: sections[1]},
		})
		if err != nil {
			t.Fatal(err)
		}
		host, err := mitm.Load(t.Context(), configuration, mitm.Options{DisableHTTP: true}, services, previous)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = host.Close() })
		return host, configuration
	}
	query := safetyRequest(dns.TypeA)
	query.ContextKey = "same-client-and-routing-policy"
	query.DialContext = func(ctx context.Context, network, target, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	lookup := func(host *mitm.Host, wantIP string, wantCached bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		response, err := host.HandleDNS(ctx, query, func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			t.Error("unexpected transparent relay")
			return nil, nil
		}, func(response *plugin.DNSResponse) error {
			if err := query.DNSPacket.ValidateResponse(response.DNSPacket, false); err != nil {
				return err
			}
			host.ObserveDNS(ctx, query, response)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		message := response.MessageCopy()
		if len(message.Answer) != 1 || message.Answer[0].(*dns.A).A.String() != wantIP || response.Cached != wantCached {
			t.Fatalf("answer=%v cached=%v, want %s cached=%v", message, response.Cached, wantIP, wantCached)
		}
		if query.ContextKey != "same-client-and-routing-policy" {
			t.Fatal("host leaked its cache namespace into caller identity")
		}
	}
	old, configuration := load(nil, "192.0.2.1")
	lookup(old, "192.0.2.1", false)
	lookup(old, "192.0.2.1", true)
	unchanged, err := mitm.Load(t.Context(), configuration, mitm.Options{DisableHTTP: true}, services, old)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unchanged.Close() })
	if !unchanged.SameInstances(old) {
		t.Fatal("identical configuration replaced DNS plugins")
	}
	lookup(unchanged, "192.0.2.1", true)
	next, _ := load(old, "192.0.2.2")
	if old.Instances()[0] != next.Instances()[0] {
		t.Fatal("unchanged cache instance should be reused")
	}
	lookup(next, "192.0.2.2", false)
	lookup(next, "192.0.2.2", true)
	lookup(old, "192.0.2.1", true) // Draining generations keep their own answers.
	ctx := plugin.WithDiagnosticDNSRequest(t.Context(), query.DNSRequest)
	explanation := next.Explain(ctx, api.ExplainRequest{DNS: &api.DiagnosticDNS{Name: "test.example.", Type: "A", Class: "IN"}}, true)
	if !explanation.Complete || !explanation.Terminal || explanation.DNS == nil || len(explanation.DNS.AnswerIPs) != 1 || explanation.DNS.AnswerIPs[0] != "192.0.2.2" {
		t.Fatalf("diagnostic lookup differs from live cache: %+v", explanation)
	}
}
