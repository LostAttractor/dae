// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"google.golang.org/protobuf/proto"
)

func writePluginGeodata(t *testing.T, dir, subnet, domain, unused string) {
	t.Helper()
	prefix := netip.MustParsePrefix(subnet)
	for name, data := range map[string]proto.Message{
		"geoip.dat": &geodata.GeoIPList{Entry: []*geodata.GeoIP{{CountryCode: "reload-test", Cidr: []*geodata.CIDR{{Ip: prefix.Addr().AsSlice(), Prefix: uint32(prefix.Bits())}}}}},
		"geosite.dat": &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
			{CountryCode: "reload-test", Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: domain}}},
			{CountryCode: "unused", Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: unused}}},
		}},
	} {
		raw, err := proto.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func pluginGeodataPlan(kind string) plugin.Plan {
	filter := []*config_parser.Function{
		{Name: "dip", Params: []*config_parser.Param{{Key: "geoip", Val: "reload-test"}}},
		{Name: "domain", Params: []*config_parser.Param{{Key: "geosite", Val: "reload-test"}}},
		{Name: "dport", Params: []*config_parser.Param{{Val: "443"}}},
	}
	rules := []*config_parser.RoutingRule{{AndFunctions: filter, Outbound: config_parser.Function{Name: "block"}}}
	switch kind {
	case "early routes":
		return plugin.Plan{EarlyRoutes: rules}
	case "late routes":
		return plugin.Plan{Routes: rules}
	default:
		return plugin.Plan{Destinations: routing.DestinationRewrites{{Filter: filter, To: []netip.Addr{netip.MustParseAddr("192.0.2.20")}}}}
	}
}

func TestMITMRefreshesGeodataWithSharedInstances(t *testing.T) {
	for _, kind := range []string{"destinations", "early routes", "late routes"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DAE_LOCATION_ASSET", dir)
			writePluginGeodata(t, dir, "198.51.100.0/24", "old.example", "unused.example")
			host, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "fixture", Plugin: &controlTestPlugin{plan: pluginGeodataPlan(kind)}})
			if err != nil {
				t.Fatal(err)
			}
			initial, err := PrepareMITM(t.Context(), host, []string{dir})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = host.Close() })
			plane := &ControlPlane{core: &controlPlaneCore{}, mitmHost: host, mitmPlan: initial.plan}
			for _, test := range []struct {
				name, subnet, domain, unused string
				changed                      bool
			}{
				{"unchanged", "198.51.100.0/24", "old.example", "unused.example", false},
				{"unused entry", "198.51.100.0/24", "old.example", "changed.example", false},
				{"geosite", "198.51.100.0/24", "new.example", "unused.example", true},
				{"geoip", "203.0.113.0/24", "old.example", "unused.example", true},
			} {
				t.Run(test.name, func(t *testing.T) {
					writePluginGeodata(t, dir, test.subnet, test.domain, test.unused)
					next, err := host.PrepareSuccessor()
					if err != nil {
						t.Fatal(err)
					}
					prepared, err := PrepareMITM(t.Context(), next, []string{dir})
					if err != nil {
						t.Fatal(err)
					}
					defer prepared.Host.Close()
					if !host.SameRuntime(prepared.Host) {
						t.Fatal("resource refresh replaced the plugin instance")
					}
					if plane.CanReplaceMITM(prepared) == test.changed {
						t.Fatal("routing reuse ignored effective geodata")
					}
					if test.changed && plane.ReplaceMITM(prepared) == nil {
						t.Fatal("changed routing accepted without kernel replacement")
					}
				})
			}
			if !reflect.DeepEqual(host.Plan(), pluginGeodataPlan(kind)) {
				t.Fatal("preparation mutated the shared plugin declaration")
			}
			for _, file := range []string{"geoip.dat", "geosite.dat"} {
				writePluginGeodata(t, dir, "198.51.100.0/24", "old.example", "unused.example")
				if err := os.WriteFile(filepath.Join(dir, file), []byte{0xff}, 0600); err != nil {
					t.Fatal(err)
				}
				next, err := host.PrepareSuccessor()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := PrepareMITM(t.Context(), next, []string{dir}); err == nil {
					t.Fatalf("accepted corrupt %s", file)
				}
			}
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			suspended, err := plane.PrepareMITMSuccessor()
			if err != nil {
				t.Fatal(err)
			}
			defer suspended.Host.Close()
			if !plane.CanReplaceMITM(suspended) || !host.SameRuntime(suspended.Host) {
				t.Fatal("suspend lost accepted resources")
			}
			rules := preparedRules{routing: testRoutingConfig(nil, "direct"), destinations: suspended.plan.Destinations}
			rules.enableMITMPlan(suspended.plan)
			if _, err := rules.compileRouting(map[string]uint8{"direct": 0, "block": 1}, nil, nil); err != nil {
				t.Fatalf("compilation reopened geodata: %v", err)
			}
		})
	}
}
