// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
)

func newHTTPRequestRouteTest(t *testing.T, routing string, extension plugin.Plugin, dial downloadTestDialer) (*ControlPlane, *RoutingMatcherBuilder, *RouteParam) {
	t.Helper()
	return newHTTPRequestRouteTestWithAuthority(t, routing, extension, dial, &mitmca.Authority{})
}

func newHTTPRequestRouteTestWithAuthority(t *testing.T, routing string, extension plugin.Plugin, dial downloadTestDialer, authority *mitmca.Authority) (*ControlPlane, *RoutingMatcherBuilder, *RouteParam) {
	t.Helper()
	host := controlTestHost(t, extension, authority)
	prepared := prepareFlowRulesForTest(t, "", routing)
	prepared.enableMITMPlan(host.Plan())
	matcher, builder := routingMatcherForTest(t, prepared)
	store, err := settings.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	clients, err := clientmatch.Parse([]string{"192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	plane := &ControlPlane{core: &controlPlaneCore{domainRegistry: newRoutingDomainRegistry()}, routingMatcher: matcher, mitmHost: host, settings: store, mitmClients: clients, sniffVerifyMode: consts.SniffVerifyMode_None}
	for _, name := range []string{"direct", "block", "proxy"} {
		plane.outbounds = append(plane.outbounds, downloadTestGroup(t, name, dial))
	}
	param := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.10:5000"), Dest: netip.MustParseAddrPort("192.0.2.20:80"), Domain: "original.example", networkType: *common.NetworkTCP4.NetworkType(),
		routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureHTTP | captureHTTPRequest, Mac: [6]byte{2, 0, 0, 0, 0, 1}}}
	return plane, builder, param
}

func TestHTTPRequestPoolUsesCurrentRouteAndMark(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	var dials atomic.Int32
	plane, builder, param := newHTTPRequestRouteTest(t, "client(blocked) -> block\nclient(marked) -> proxy(mark:91)\ndport(80) -> proxy(mark:92)",
		rewriteTestPlugin(t, map[string]string{"/old": "http://original.example/new"}),
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
		})
	option, planner, release, err := plane.prepareHTTPRoute(context.Background(), param.Domain, param)
	if err != nil || option != nil || planner == nil || release != nil {
		t.Fatalf("premature selection: %+v, %v", option, err)
	}
	handler, closePools := plane.mitmHost.Handler("http", "original.example", 80, planner)
	defer closePools()
	request := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "http://original.example/old", nil))
		if w.Code != want {
			t.Fatalf("HTTP status=%d, want %d: %s", w.Code, want, w.Body.String())
		}
	}
	request(200)
	request(200)
	if dials.Load() != 1 {
		t.Fatal("unchanged route did not reuse its upstream connection")
	}
	if err := builder.SetClientMembers(plane.routingMatcher, "marked", [][6]byte{param.routingResult.Mac}, false); err != nil {
		t.Fatal(err)
	}
	request(200)
	if dials.Load() != 2 {
		t.Fatal("new mark reused a connection from the previous route")
	}
	if err := builder.SetClientMembers(plane.routingMatcher, "blocked", [][6]byte{param.routingResult.Mac}, false); err != nil {
		t.Fatal(err)
	}
	request(502)
	if dials.Load() != 2 {
		t.Fatal("blocked target opened a connection")
	}
	if param.routingResult.Outbound != uint8(consts.OutboundControlPlaneRouting) || param.routingResult.Mark != 0 {
		t.Fatal("HTTP requests mutated ingress routing state")
	}
}

func TestHTTPRequestAdmissionAndLocalResponses(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		denied bool
	}{
		{"redirect", 302, false},
		{"reject", 403, false},
		{"client exclusion", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			extension := mitmRoutingPlugin("original.example")
			extension.plan.Scopes[0].PreserveRoute = false
			extension.handle = func(*plugin.Exchange, plugin.Handler) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Header: http.Header{"Location": {"http://new.example/"}}, Body: http.NoBody}, nil
			}
			plane, _, param := newHTTPRequestRouteTest(t, "dport(80) -> block", extension, func(context.Context, string, string) (net.Conn, error) {
				t.Error("unexpected upstream dial")
				return nil, net.ErrClosed
			})
			if test.denied {
				plane.mitmClients = clientmatch.Matcher{}
			}
			option, planner, release, err := plane.prepareHTTPRoute(context.Background(), param.Domain, param)
			if err != nil {
				t.Fatal(err)
			}
			if release != nil {
				defer release()
			}
			if test.denied {
				if planner != nil || option == nil || option.Outbound.Name != "block" {
					t.Fatal("client exclusion bypassed original routing")
				}
				return
			}
			if option != nil || planner == nil {
				t.Fatal("local response was stopped by original target block")
			}
			handler, closePools := plane.mitmHost.Handler("http", "original.example", 80, planner)
			defer closePools()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "http://original.example/old", nil))
			if w.Code != test.status {
				t.Fatalf("response=%d, want %d: %s", w.Code, test.status, w.Body.String())
			}
		})
	}
}

func TestPendingHTTPWithoutHostnameUsesDNSEvidence(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprint(ambiguous), func(t *testing.T) {
			plane, _, param := newHTTPRequestRouteTest(t, "domain(full: original.example) -> block", rewriteTestPlugin(t, map[string]string{"/old": "http://original.example/new"}), func(context.Context, string, string) (net.Conn, error) {
				t.Error("selection must not dial")
				return nil, net.ErrClosed
			})
			param.Domain = "" // No usable SNI/Host, so the candidate cannot enter MITM.
			registry, matcher := plane.core.domainRegistry, plane.routingMatcher
			registry.Upsert("original.example.", param.Dest.Addr(), matcher.domainMatcher.MatchDomainBitmap("original.example"), 3600, time.Now())
			if ambiguous {
				registry.Upsert("outside.example.", param.Dest.Addr(), matcher.domainMatcher.MatchDomainBitmap("outside.example"), 3600, time.Now())
			}
			option, planner, _, err := plane.prepareHTTPRoute(context.Background(), param.Domain, param)
			if planner != nil {
				t.Fatal("hostname-less candidate entered MITM")
			}
			if ambiguous {
				if err == nil {
					t.Fatal("ambiguous domain route silently became direct")
				}
			} else if err != nil || option.Outbound.Name != "block" {
				t.Fatalf("lost original DNS routing evidence: %+v, %v", option, err)
			}
			// An explicit IP URL has a known logical target with no hostname;
			// the same physical IP must not borrow original.example's policy.
			option, err = plane.selectHTTPAddress("tcp", param.Src, *param.routingResult, "", param.Dest)
			if err != nil || option.Outbound.Name != "direct" {
				t.Fatalf("IP URL borrowed DNS identity: %+v, %v", option, err)
			}
		})
	}
}

func TestHTTP2RequestTargetsRemainIndependent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer backend.Close()
	plane, _, param := newHTTPRequestRouteTest(t,
		"dip(198.51.100.1) -> proxy(mark:91)\ndip(198.51.100.2) -> direct\ndip(192.0.2.20,203.0.113.1) -> block",
		rewriteTestPlugin(t, map[string]string{"/proxy": "http://198.51.100.1:8080/ok", "/direct": "http://198.51.100.2:8080/ok", "/blocked": "http://203.0.113.1:8080/ok"}),
		func(context.Context, string, string) (net.Conn, error) {
			t.Error("blocked or unplanned dial")
			return nil, net.ErrClosed
		})
	param.Dest = netip.MustParseAddrPort("192.0.2.20:443")
	before := *param.routingResult
	for index, name := range map[int]string{0: "direct", 2: "proxy"} {
		plane.outbounds[index] = downloadTestGroup(t, name, func(ctx context.Context, _, address string) (net.Conn, error) {
			want := "198.51.100.1:8080"
			if name == "direct" {
				want = "198.51.100.2:8080"
			}
			if address != want {
				t.Errorf("concurrent %s route dialed %s, want %s", name, address, want)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
		})
	}
	option, planner, release, err := plane.prepareHTTPRoute(context.Background(), param.Domain, param)
	if err != nil || option != nil || planner == nil || release != nil {
		t.Fatalf("request setup: %+v, %v", option, err)
	}
	handler, closePools := plane.mitmHost.Handler("https", "original.example", 443, planner)
	defer closePools()
	frontend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("test did not exercise HTTP/2")
		}
		handler.ServeHTTP(w, r)
	}))
	frontend.EnableHTTP2 = true
	frontend.StartTLS()
	defer frontend.Close()
	client := frontend.Client()
	client.Timeout = 5 * time.Second
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	var wg sync.WaitGroup
	for i := range 18 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path, status := []string{"proxy", "direct", "blocked"}[i%3], http.StatusOK
			if path == "blocked" {
				status = http.StatusBadGateway
			}
			request, err := http.NewRequest("GET", frontend.URL+"/"+path, nil)
			if err != nil {
				t.Error(err)
				return
			}
			request.Host = "original.example"
			response, err := client.Do(request)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != status || (status == http.StatusOK && string(body) != "ok") {
				t.Errorf("%s: status=%d body=%q err=%v", path, response.StatusCode, body, err)
			}
		}()
	}
	wg.Wait()
	if *param.routingResult != before {
		t.Fatal("concurrent requests changed shared ingress identity")
	}
}
