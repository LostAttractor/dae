// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/settings"
	dnsmessage "github.com/miekg/dns"
)

func TestMITMURLRewriteRoutesEffectiveTarget(t *testing.T) {
	for _, test := range []struct {
		name, url, outbound, target string
		status                      int
		deferred                    bool
	}{
		{"path only retains valid route", "http://original.example/changed?q=1", "direct", "192.0.2.20:80", 200, false},
		{"deferred unchanged target still blocked", "http://original.example/changed?q=1", "", "", 502, true},
		{"new IP and port", "http://198.51.100.4:8080/new", "proxy", "198.51.100.4:8080", 200, true},
		{"new hostname", "http://new.example:8080/new", "proxy", "198.51.100.4:8080", 200, true},
		{"same host new port", "http://original.example:8081/new", "proxy", "198.51.100.4:8081", 200, true},
		{"rewritten URL then DNAT", "http://198.51.100.9:8080/new", "proxy", "198.51.100.40:8080", 200, true},
		{"new target blocked", "http://203.0.113.8/new", "", "", 502, true},
		{"new hostname blocked", "http://blocked.example/new", "", "", 502, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "ok")
			}))
			t.Cleanup(upstream.Close)
			var mu sync.Mutex
			var gotOutbound, gotTarget string
			dials := 0
			groups := make([]*outbound.DialerGroup, 0, 3)
			for _, name := range []string{"direct", "block", "proxy"} {
				groups = append(groups, surgeDownloadTestGroup(t, name, func(ctx context.Context, _, address string) (net.Conn, error) {
					mu.Lock()
					gotOutbound, gotTarget = name, address
					dials++
					mu.Unlock()
					return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
				}))
			}
			prepared := prepareFlowRulesForTest(t, "dip(198.51.100.9) -> dnat(198.51.100.40)", `
dip(203.0.113.8) -> block
domain(full: blocked.example) -> block
domain(full: original.example) && dport(8080) -> block
dip(198.51.100.4,198.51.100.40) && sip(192.0.2.10) && sport(5000) && pname(app) && dscp(46) && dport(8080,8081) -> proxy(mark:91)
domain(full: original.example) -> block`)
			matcher, _ := surgeRoutingMatcher(t, prepared)
			plane := &ControlPlane{core: &controlPlaneCore{domainRegistry: newDomainRegistry(32, 32, time.Second)}, routingMatcher: matcher, outbounds: groups, fallbackResolver: "192.0.2.53:53", sniffVerifyMode: consts.SniffVerifyMode_None}
			attachSurgeDownloadTestDNS(t, plane, "test", "accept", func(message *dnsmessage.Msg) {
				message.Response = true
				message.Answer = []dnsmessage.RR{&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: message.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.4")}}
			})
			module, err := surge.Parse("[MITM]\nhostname = original.example:80\n[URL Rewrite]\n^http://original.example/old$ "+test.url+" header\n", nil)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := surge.NewEngine(surge.EngineOptions{Modules: []*surge.Module{module}, Runtime: &surge.Runtime{}, MaxBodySize: 1 << 20, MaxConcurrentScripts: 1, ScriptTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			// This exercises the HTTP handler; no TLS handshake uses the CA.
			host, err := mitm.New(mitm.Options{Authority: &mitmca.Authority{}}, mitm.Instance{ID: "surge", Type: "surge", Plugin: engine})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = host.Close() })
			selected, err := groups[0].Select(common.NetworkTCP4.NetworkType())
			if err != nil {
				t.Fatal(err)
			}
			option := &DialOption{Outbound: groups[0], Dialer: selected, Direct: true, DialTarget: "192.0.2.20:80", NetworkType: *common.NetworkTCP4.NetworkType()}
			identity := bpfRoutingResult{Ifindex: 7, Dscp: 46, CaptureFlags: captureHTTP, Mark: 37, Must: 1}
			copy(identity.Pname[:], "app")
			planner := plane.mitmUpstreamPlanner("tcp", "original.example", netip.MustParseAddrPort("192.0.2.10:5000"), netip.MustParseAddrPort(option.DialTarget), identity, option)
			if test.deferred {
				plane.mitmHost = host
				plane.settings, err = settings.Open(filepath.Join(t.TempDir(), "state.json"))
				if err != nil {
					t.Fatal(err)
				}
				plane.mitmClients, err = clientmatch.Parse([]string{"192.0.2.10"})
				if err != nil {
					t.Fatal(err)
				}
				pending := identity
				pending.CaptureFlags = captureHTTP | captureHTTPRequest
				pending.Outbound = uint8(consts.OutboundControlPlaneRouting)
				param := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.10:5000"), Dest: netip.MustParseAddrPort(option.DialTarget), Domain: "original.example", routingResult: &pending, networkType: *common.NetworkTCP4.NetworkType()}
				var selected *DialOption
				var release func()
				selected, planner, release, err = plane.prepareHTTPRoute(context.Background(), param.Domain, param)
				if err != nil || selected != nil || planner == nil || release != nil {
					t.Fatalf("request capture committed old target routing: option=%+v planner=%v release=%v err=%v", selected, planner != nil, release != nil, err)
				}
			}
			handler, closeTransport := host.Handler("http", "original.example", 80, planner)
			defer closeTransport()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "http://original.example/old", nil))
			if response.Code != test.status {
				t.Fatalf("rewrite returned %d: %s", response.Code, response.Body.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if gotOutbound != test.outbound || gotTarget != test.target || (test.status == 502 && dials != 0) {
				t.Fatalf("upstream=%s/%s dials=%d, want=%s/%s", gotOutbound, gotTarget, dials, test.outbound, test.target)
			}
			if identity.Mark != 37 || identity.Must != 1 {
				t.Fatal("rewritten request mutated original flow identity")
			}
		})
	}
}
