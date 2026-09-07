// SPDX-License-Identifier: AGPL-3.0-only

package surge

import "testing"

func TestHostProxyScope(t *testing.T) {
	enabled, err := Parse("[Host]\n192.0.2.1 = 192.0.2.2\n[General]\nuse-local-host-item-for-proxy=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := Parse("[Host]\n192.0.2.3 = 192.0.2.4", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: EngineOptions{Modules: []*Module{enabled, disabled}}}
	rules := engine.Plan().Destinations
	if len(rules) != 2 || !rules[0].Proxy || rules[1].Proxy {
		t.Fatalf("General order or module scope changed Host options: %+v", rules)
	}
}

func TestHostMappingSyntax(t *testing.T) {
	for _, source := range []string{
		"[Host]\n192.0.2.1", "[Host]\n192.0.2.1 =", "[Host]\n192.0.2.1 = 192.0.2.2,invalid",
		"[General]\nuse-local-host-item-for-proxy = invalid",
	} {
		if _, err := Parse(source, nil); err == nil {
			t.Fatalf("accepted invalid module: %s", source)
		}
	}
	module, err := Parse("[Host]\nexample.com = 192.0.2.1\n[General]\nipv6=true", nil)
	if err != nil || len(module.Hosts) != 1 || len(module.Warnings) != 1 {
		t.Fatalf("unsupported entries: %+v, %v", module, err)
	}
}
