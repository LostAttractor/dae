// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func hostDNSRequest(t *testing.T, name string, typ uint16) *plugin.DNSRequest {
	t.Helper()
	m := new(dns.Msg).SetQuestion(name, typ)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &plugin.DNSRequest{Message: m, Wire: wire, Network: "udp", Destination: netip.MustParseAddrPort("192.0.2.53:53")}
}

func TestSurgeDNSHostAnswers(t *testing.T) {
	m := moduleScopeModule(t, "dns", "", `[Host]
exact.example = 192.0.2.1, 2001:db8::1
*.example = 198.51.100.1
alias.test = exact.example
loop.test = loop.test
`, nil)
	e := moduleScopeEngine(t, m)
	for _, test := range []struct {
		name    string
		typ     uint16
		answers int
		first   uint16
	}{
		{"exact.example.", dns.TypeA, 1, dns.TypeA}, {"exact.example.", dns.TypeAAAA, 1, dns.TypeAAAA}, {"exact.example.", dns.TypeANY, 2, dns.TypeA},
		{"exact.example.", dns.TypeMX, 0, 0}, {"wild.example.", dns.TypeA, 1, dns.TypeA}, {"alias.test.", dns.TypeA, 2, dns.TypeCNAME},
	} {
		t.Run(test.name+dns.TypeToString[test.typ], func(t *testing.T) {
			req := hostDNSRequest(t, test.name, test.typ)
			response, err := e.WrapDNS(func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) {
				t.Fatal("static Host reached upstream")
				return nil, nil
			})(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Message.Answer) != test.answers || response.Message.Id != req.Message.Id || response.Message.Question[0] != req.Message.Question[0] || response.Message.AuthenticatedData {
				t.Fatalf("Host response: %s", response.Message)
			}
			if test.answers > 0 && response.Message.Answer[0].Header().Rrtype != test.first {
				t.Fatal("alias or address family lost")
			}
		})
	}
	if _, err := e.WrapDNS(nil)(t.Context(), hostDNSRequest(t, "loop.test.", dns.TypeA)); err == nil {
		t.Fatal("alias loop accepted")
	}
}

func TestSurgeDNSScriptsAndServers(t *testing.T) {
	for _, test := range []struct {
		source string
		count  int
		server string
		fails  bool
	}{
		{`if($domain!=="script.test")throw Error("domain");$done({addresses:["192.0.2.1","2001:db8::1"],ttl:42})`, 1, "", false},
		{`$done({server:"192.0.2.54:5353"})`, 0, "192.0.2.54:5353", false},
		{`$done({servers:["https://dns.example/dns-query","tls://dns.example"]})`, 0, "resolver", false},
		{`$done({})`, 0, "192.0.2.53:53", false},
		{`$done({address:"192.0.2.1",server:"192.0.2.53"})`, 0, "", true},
	} {
		t.Run(test.source, func(t *testing.T) {
			m := moduleScopeModule(t, "dns", "", "[Host]\nscript.test=script:answer\n[Script]\nanswer=type=dns,script-path=answer.js", map[string]string{"answer": test.source})
			e := moduleScopeEngine(t, m)
			req := hostDNSRequest(t, "script.test.", dns.TypeA)
			var target string
			req.Resolve = func(_ context.Context, _ *plugin.DNSRequest, servers []string) (*plugin.DNSResponse, error) {
				target = "resolver"
				if len(servers) != 2 {
					t.Fatal("multiple servers lost")
				}
				return hostAddressResponse(req, nil, 0), nil
			}
			response, err := e.WrapDNS(func(_ context.Context, r *plugin.DNSRequest) (*plugin.DNSResponse, error) {
				target = r.Destination.String()
				if target == "192.0.2.54:5353" && !r.ServerAssigned {
					t.Fatal("server priority lost")
				}
				return hostAddressResponse(r, nil, 0), nil
			})(t.Context(), req)
			if (err != nil) != test.fails {
				t.Fatalf("script error=%v", err)
			}
			if test.fails {
				return
			}
			if target != test.server || len(response.Message.Answer) != test.count {
				t.Fatalf("script result: %s %v", target, response)
			}
			if test.count != 0 && response.Message.Answer[0].Header().Ttl != 42 {
				t.Fatal("script TTL lost")
			}
		})
	}
}

func TestSurgeHostDomainSets(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"hosts.sgmodule": "[Host]\nDOMAIN-SET:domains.list=192.0.2.1\nRULE-SET:rules.list=2001:db8::1", "domains.list": ".example.com\nexact.test\n", "rules.list": "DOMAIN-SUFFIX,example.net\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Load(t.Context(), "file:hosts.sgmodule", nil, LoadOptions{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.DNSHosts) != 2 || !m.DNSHosts[0].Match("sub.example.com") || !m.DNSHosts[0].Match("exact.test") || m.DNSHosts[0].Match("badexact.test") || !m.DNSHosts[1].Match("sub.example.net") {
		t.Fatalf("Host set predicates: %+v", m.DNSHosts)
	}
}

func TestSurgeHostSetCannotNegateUnknownContext(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"hosts.sgmodule": "[Host]\nRULE-SET:rules.list=192.0.2.1",
		"rules.list":     "NOT,((IP-CIDR,192.0.2.0/24))\nDOMAIN,allowed.example\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Load(t.Context(), "file:hosts.sgmodule", nil, LoadOptions{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.DNSHosts) != 1 || !m.DNSHosts[0].Match("allowed.example") || m.DNSHosts[0].Match("unrelated.example") {
		t.Fatal("Host set widened an unsupported predicate")
	}
}
