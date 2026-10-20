// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	dns "github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func TestReloadRefreshesGeodata(t *testing.T) {
	dir := t.TempDir()
	write := func(domain string) {
		t.Helper()
		data, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{CountryCode: "audit", Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: domain}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	source, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	services := plugin.Services{BaseDir: dir, Interfaces: source}
	load := func(previous []*pluginhost.Instance) pluginhost.PreparedInstance {
		sections, err := config_parser.Parse("router { routing { request { qname(geosite:audit) -> reject fallback:asis } } }")
		if err != nil {
			t.Fatal(err)
		}
		conf, err := pluginhost.Configure(map[string]plugin.Definition{"router": Plugin}, []plugin.Spec{{ID: "router", Type: "router", Config: sections[0]}})
		if err != nil {
			t.Fatal(err)
		}
		instances, err := conf.Prepare(t.Context(), services, previous)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { instances[0].Release() })
		return instances[0]
	}
	rejects := func(instance pluginhost.PreparedInstance, domain string) bool {
		called := false
		query := &plugin.DNSExchange{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetQuestion(domain, dns.TypeA)), Source: netip.MustParseAddrPort("192.0.2.2:10000"), OriginalDestination: netip.MustParseAddrPort("192.0.2.53:53"), Destination: netip.MustParseAddrPort("192.0.2.53:53"), Network: "udp"}
		_, err := instance.Plugin.(plugin.DNSPlugin).WrapDNS(func(_ context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			called = true
			return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetReply(request.MessageCopy()))}, nil
		})(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		return !called
	}
	write("old.test")
	first := load(nil)
	if !rejects(first, "old.test.") {
		t.Fatal("fixture did not load initial geodata")
	}
	unchanged := load([]*pluginhost.Instance{first.Instance})
	if unchanged.Instance != first.Instance {
		t.Fatal("unchanged resources rebuilt the router")
	}
	write("new.test")
	next := load([]*pluginhost.Instance{first.Instance})
	fresh := load(nil)
	t.Logf("reused=%v; reload rejects old=%v new=%v; fresh rejects old=%v new=%v", first.Instance == next.Instance, rejects(next, "old.test."), rejects(next, "new.test."), rejects(fresh, "old.test."), rejects(fresh, "new.test."))
	if !rejects(first, "old.test.") || rejects(first, "new.test.") {
		t.Fatal("preparation mutated the running router")
	}
	if rejects(next, "old.test.") || !rejects(next, "new.test.") {
		t.Fatal("unchanged configuration reload kept stale geodata")
	}
}
