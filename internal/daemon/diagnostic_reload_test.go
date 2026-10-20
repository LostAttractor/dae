// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	verify "github.com/daeuniverse/dae/component/mitm/verify"
	"github.com/daeuniverse/dae/component/plugin"
	cache "github.com/daeuniverse/dae/plugins/dns-cache"
	dns "github.com/miekg/dns"
)

func TestReloadRetainsDiagnosticAndDNSCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "key.pem")
	if err := localca.Generate(cert, key, "audit", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := localca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	conf := mitmConfigForTest(t, "mitm { enabled:true } plugins { cache { type:dns-cache } }")
	conf.Global.APIPort = 9080
	plugins, err := configurePlugins(conf, map[string]plugin.Definition{"dns-cache": cache.Plugin})
	if err != nil {
		t.Fatal(err)
	}
	load := func(previous *mitm.Host) *mitm.Host {
		prepared, err := loadMITM(t.Context(), conf, authority, http.DefaultClient, http.DefaultClient, plugins, previous, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { prepared.Host.Close() })
		return prepared.Host
	}
	calls := 0
	lookup := func(host *mitm.Host) bool {
		request := &plugin.DNSExchange{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetQuestion("example.test.", dns.TypeA)), Network: "udp", Destination: netip.MustParseAddrPort("192.0.2.53:53")}
		response, err := host.HandleDNS(t.Context(), request, func(_ context.Context, q *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			calls++
			answer := new(dns.Msg).SetReply(q.MessageCopy())
			answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.IPv4(192, 0, 2, 1)}}
			return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(answer), ReceivedAt: time.Now()}, nil
		}, func(*plugin.DNSResponse) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return response.Cached
	}
	first := load(nil)
	if lookup(first) || !lookup(first) {
		t.Fatal("cache fixture failed")
	}
	next := load(first)
	cached := lookup(next)
	t.Logf("DNS cache instance reused=%v; SameRuntime=%v; post-reload cache hit=%v; upstream calls=%d", first.Instances()[1] == next.Instances()[1], first.SameRuntime(next), cached, calls)
	if !cached || !first.SameRuntime(next) {
		t.Fatal("HTTP-only diagnostic replacement changed DNS cache and host identity")
	}
	service := first.Instances()[0].Plugin.(*verify.Service)
	generation := service.Generation()
	next.Close()
	if service.Generation() != generation || !lookup(first) {
		t.Fatal("discarding a candidate changed the running host")
	}
	conf.Global.APIMITMTestIPv4 = "203.0.113.253"
	changed := load(first)
	if changed.SameRuntime(first) {
		t.Fatal("changed diagnostic targets reused the old runtime")
	}
}
