// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"reflect"
	"strings"
	"testing"
)

func TestHostProxyCompatibilityWarning(t *testing.T) {
	const hosts = "[Host]\n192.0.2.1 = 192.0.2.2\nexample.com = 192.0.2.3, 2001:db8::1\n"
	const enabled = "[General]\nuse-local-host-item-for-proxy = true\n"
	const disabled = "[General]\nuse-local-host-item-for-proxy = false\n"
	var modules []*Module
	for _, test := range []struct {
		name, source string
		warnings     int
	}{
		{"absent", hosts, 1},
		{"false", disabled + hosts, 1},
		{"true before Host", enabled + hosts, 0},
		{"true after Host", hosts + enabled, 0},
		{"last value wins", hosts + enabled + disabled, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			module, err := Parse(test.source, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(module.Hosts) != 2 || len(module.Warnings) != test.warnings {
				t.Fatalf("Host mappings or compatibility warnings: %+v", module)
			}
			for _, warning := range module.Warnings {
				for _, want := range []string{"[Host]", "direct and proxy", "use-local-host-item-for-proxy", "differs from Surge"} {
					if !strings.Contains(warning, want) {
						t.Errorf("warning missing %q: %s", want, warning)
					}
				}
			}
			modules = append(modules, module)
		})
	}
	engine := &Engine{options: EngineOptions{Modules: modules}}
	rules := engine.Plan().Destinations
	if len(rules) != 2*len(modules) {
		t.Fatalf("lost module mappings: %+v", rules)
	}
	for i, module := range modules {
		if !reflect.DeepEqual(rules[i*2:(i+1)*2], modules[0].Hosts) {
			t.Fatal("compatibility option changed the destination plan")
		}
		if !reflect.DeepEqual(engine.Status().Modules[i].Warnings, module.Warnings) {
			t.Fatal("compatibility warnings leaked between modules")
		}
	}
	for _, source := range []string{"[Host]\n", disabled, disabled + "[Host]\n"} {
		module, err := Parse(source, nil)
		if err != nil || len(module.Warnings) != 0 {
			t.Fatalf("unused Host must not warn: %+v, %v", module, err)
		}
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
	if err != nil || len(module.Hosts) != 1 || len(module.Warnings) != 2 {
		t.Fatalf("unsupported entries: %+v, %v", module, err)
	}
}
