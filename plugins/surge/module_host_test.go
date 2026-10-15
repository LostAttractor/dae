// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"testing"
)

func TestHostDNSAndLiteralDestinationPlans(t *testing.T) {
	for _, enabled := range []string{"false", "true"} {
		module, err := Parse("[General]\nuse-local-host-item-for-proxy="+enabled+"\n[Host]\n192.0.2.1 = 192.0.2.2\nexample.com = 192.0.2.3, 2001:db8::1", nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := newTestEngine(t, EngineOptions{Modules: []*Module{module}})
		plan := engine.Plan()
		if len(plan.Destinations) != 1 || len(plan.DNS) != 1 || len(module.DNSHosts) != 1 || len(module.Warnings) != 0 {
			t.Fatalf("domain Host must be DNS-only: module=%+v plan=%+v", module, plan)
		}
		direct, directMatch := engine.UseDNSAddress("example.com", false)
		proxy, proxyMatch := engine.UseDNSAddress("example.com", true)
		if !directMatch || !proxyMatch || !direct || proxy != (enabled == "true") {
			t.Fatal("Host proxy address policy lost")
		}
	}
}

func TestHostMappingSyntax(t *testing.T) {
	for _, source := range []string{
		"[Host]\n192.0.2.1", "[Host]\n192.0.2.1 =", "[Host]\n192.0.2.1 = 192.0.2.2,invalid",
		"[General]\nuse-local-host-item-for-proxy = invalid", "[Host]\na = server:invalid", "[Host]\na = script:missing",
	} {
		if _, err := Parse(source, nil); err == nil {
			t.Fatalf("accepted invalid module: %s", source)
		}
	}
	module, err := Parse("[Host]\nexample.com = 192.0.2.1\n[General]\nipv6=true", nil)
	if err != nil || len(module.DNSHosts) != 1 || len(module.Hosts) != 0 || len(module.Warnings) != 1 {
		t.Fatalf("unsupported entries: %+v, %v", module, err)
	}
}

func TestHostSetURLAssignmentDelimiter(t *testing.T) {
	for _, kind := range []string{"DOMAIN-SET", "RULE-SET"} {
		for _, target := range []string{"192.0.2.1", "server:https://dns.example/query?token=def"} {
			for _, separator := range []string{" = ", "\t=\t"} {
				source := "https://lists.example/domains?token=abc&key=123=="
				m, err := Parse("[Host]\n"+kind+":"+source+separator+target, nil)
				if err != nil {
					t.Fatal(err)
				}
				if len(m.DNSHosts) != 1 || m.DNSHosts[0].SetSource != source || m.DNSHosts[0].SetKind != kind {
					t.Fatalf("URL assignment changed: %+v", m.DNSHosts)
				}
				if target != "192.0.2.1" && m.DNSHosts[0].Servers[0] != "https://dns.example/query?token=def" {
					t.Fatal("target URL query lost")
				}
			}
		}
	}
}
