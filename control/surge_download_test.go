// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type surgeDownloadTestDialer func(context.Context, string, string) (net.Conn, error)

func (d surgeDownloadTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d(ctx, network, address)
}

func (surgeDownloadTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func surgeDownloadTestGroup(t *testing.T, name string, dial surgeDownloadTestDialer) *outbound.DialerGroup {
	t.Helper()
	option := &dialer.GlobalOption{}
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: dial}), option,
		&dialer.Property{Name: name, Link: "test://" + t.Name() + "/" + name}, false, "")
	group := outbound.NewDialerGroup(option, name, outbound.GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = group.Close() })
	return group
}

func surgeDownloadTestPlane(t *testing.T, rules string, groups ...*outbound.DialerGroup) *ControlPlane {
	t.Helper()
	sections, err := config_parser.Parse("global {}\nrouting {\n" + rules + "\nfallback: direct\n}")
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]uint8, len(groups))
	for i, group := range groups {
		ids[group.Name] = uint8(i)
	}
	builder, err := NewRoutingMatcherBuilder(configuration.Routing.Rules, ids, nil, "direct", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	return &ControlPlane{core: &controlPlaneCore{}, outbounds: groups, routingMatcher: matcher, fallbackResolver: "192.0.2.53:53"}
}

type surgeDownloadTestDNS func(*dnsmessage.Msg)

func (f surgeDownloadTestDNS) ForwardDNS(_ context.Context, message *dnsmessage.Msg) error {
	f(message)
	return nil
}
func (surgeDownloadTestDNS) Close() error { return nil }

func attachSurgeDownloadTestDNS(t *testing.T, c *ControlPlane, request, response string, answer surgeDownloadTestDNS) *config.Dns {
	t.Helper()
	configuration := &config.Dns{
		Upstream: []config.KeyableString{"test:tcp://192.0.2.53:53"},
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString(request)},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString(response)},
		},
	}
	controller, err := c.newDNSController(configuration, preparedRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	c.dnsController = controller
	upstream, err := controller.routing.GetUpstream(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	argument, err := c.chooseBestDnsDialer(&udpRequest{src: surgeDownloadSource(upstream.Ip4), routingResult: &bpfRoutingResult{}}, upstream)
	if err != nil {
		t.Fatal(err)
	}
	controller.dnsForwarderCache[makeDNSForwarderKey(upstream, argument)] = answer
	return configuration
}

func TestSurgeDownloadRoutesResolvedDestination(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "ip", true: "domain"}[override], func(t *testing.T) {
			var calls []string
			group := func(name string) *outbound.DialerGroup {
				return surgeDownloadTestGroup(t, name, func(ctx context.Context, network, address string) (net.Conn, error) {
					calls = append(calls, name+" "+network+" "+address)
					if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > consts.DefaultDialTimeout {
						t.Error("download dial has no bounded timeout")
					}
					conn, peer := net.Pipe()
					_ = peer.Close()
					return conn, nil
				})
			}
			c := surgeDownloadTestPlane(t, "domain(full: raw.example) && dip(198.51.100.0/24) && dport(443) -> proxy", group("direct"), group("block"), group("proxy"), group("unused"))
			c.dialTargetOverride = override
			attachSurgeDownloadTestDNS(t, c, "test", "accept", func(message *dnsmessage.Msg) {
				question := message.Question[0]
				if question.Name != "raw.example." || question.Qtype != dnsmessage.TypeA {
					t.Errorf("unexpected DNS query: %+v", question)
				}
				message.Response = true
				message.Answer = []dnsmessage.RR{
					testARecord("unrelated.example.", "203.0.113.8"),
					&dnsmessage.CNAME{Hdr: dnsmessage.RR_Header{Name: question.Name, Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 60}, Target: "edge.example."},
					testARecord("edge.example.", "198.51.100.4"),
				}
			})
			conn, err := surgeDownloadDialContext(c)(context.Background(), "tcp", "raw.example:443")
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			want := "proxy tcp 198.51.100.4:443"
			if override {
				want = "proxy tcp raw.example:443"
			}
			if !reflect.DeepEqual(calls, []string{want}) {
				t.Fatalf("download dials = %v; want %s", calls, want)
			}
		})
	}
}

func TestSurgeDownloadHonorsDNSRejection(t *testing.T) {
	for _, stage := range []string{"request", "response"} {
		t.Run(stage, func(t *testing.T) {
			unexpected := surgeDownloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
				t.Error("DNS-rejected download reached a TCP dialer")
				return nil, net.ErrClosed
			})
			c := surgeDownloadTestPlane(t, "", unexpected)
			request, response := "test", "reject"
			if stage == "request" {
				request, response = "reject", "accept"
			}
			queries := 0
			attachSurgeDownloadTestDNS(t, c, request, response, func(message *dnsmessage.Msg) {
				queries++
				message.Response = true
				message.Answer = []dnsmessage.RR{testARecord(message.Question[0].Name, "198.51.100.4")}
			})
			_, err := surgeDownloadDialContext(c)(context.Background(), "tcp4", "raw.example:443")
			if err == nil || !strings.Contains(err.Error(), "no A addresses") {
				t.Fatalf("DNS rejection = %v", err)
			}
			if (stage == "request" && queries != 0) || (stage == "response" && queries != 1) {
				t.Fatalf("upstream queries = %d at %s rejection", queries, stage)
			}
		})
	}
}

func TestSurgeDownloadHonorsBlockAndConnectivityFallback(t *testing.T) {
	for _, test := range []struct {
		name, rules string
		fallback    consts.OutboundIndex
		wantDirect  bool
	}{
		{"direct", "", consts.OutboundBlock, true},
		{"block", "dport(443) -> block", consts.OutboundDirect, false},
		{"unavailable to block", "dport(443) -> unavailable", consts.OutboundBlock, false},
		{"unavailable to direct", "dport(443) -> unavailable", consts.OutboundDirect, true},
		{"skip unavailable", "dport(443) -> unavailable(skip_while_noalive)\ndport(443) -> direct", consts.OutboundBlock, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directCalls := 0
			direct := surgeDownloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
				directCalls++
				conn, peer := net.Pipe()
				_ = peer.Close()
				return conn, nil
			})
			unexpected := func(context.Context, string, string) (net.Conn, error) {
				t.Error("download dialed a blocked or unhealthy path")
				return nil, net.ErrClosed
			}
			block := surgeDownloadTestGroup(t, "block", unexpected)
			option := &dialer.GlobalOption{}
			d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: surgeDownloadTestDialer(unexpected)}), option,
				&dialer.Property{Name: "unavailable"}, true, "")
			unavailable := outbound.NewDialerGroup(option, "unavailable", outbound.GroupKindSelector,
				[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
			t.Cleanup(func() { _ = unavailable.Close() })
			c := surgeDownloadTestPlane(t, test.rules, direct, block, unavailable)
			c.noConnectivityOutbound = test.fallback
			c.routingMatcher.outboundUsable = func(index uint8, _ consts.L4ProtoType, version consts.IpVersionType) bool {
				_, err := c.outbounds[index].Select(&common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: version.ToIpVersionStr()})
				return err == nil
			}
			conn, err := surgeDownloadDialContext(c)(context.Background(), "tcp", "198.51.100.4:443")
			if test.wantDirect {
				if err != nil || directCalls != 1 {
					t.Fatalf("direct calls = %d, error = %v", directCalls, err)
				}
				_ = conn.Close()
			} else if err == nil || !strings.Contains(err.Error(), "blocked by routing") || directCalls != 0 {
				t.Fatalf("blocked result = %v; direct calls = %d", err, directCalls)
			}
		})
	}
}

func TestSurgeDownloadRoutesRedirectDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://203.0.113.8/module.sgmodule", http.StatusFound)
	}))
	defer server.Close()
	calls := 0
	direct := surgeDownloadTestGroup(t, "direct", func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		return new(net.Dialer).DialContext(ctx, network, address)
	})
	block := surgeDownloadTestGroup(t, "block", func(context.Context, string, string) (net.Conn, error) {
		t.Error("redirect bypassed the block rule")
		return nil, net.ErrClosed
	})
	c := surgeDownloadTestPlane(t, "dip(203.0.113.8) -> block", direct, block)
	client, closeDownloads := newSurgeDownloadClient(c)
	defer closeDownloads()
	_, err := client.Get(server.URL)
	if err == nil || !strings.Contains(err.Error(), "blocked by routing") || calls != 1 {
		t.Fatalf("redirect error = %v, direct calls = %d", err, calls)
	}
}

func TestSurgeDownloadStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	direct := surgeDownloadTestGroup(t, "direct", func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	client, closeDownloads := newSurgeDownloadClient(surgeDownloadTestPlane(t, "", direct))
	defer closeDownloads()
	transport := client.Transport.(*http.Transport)
	dial := transport.DialContext
	dialDone := make(chan error, 1)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		dialDone <- err
		return conn, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://198.51.100.4/module.sgmodule", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		response, err := client.Do(req)
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request did not start a download dial")
	}
	cancel()
	select {
	case err := <-requestDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled HTTP request = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request did not stop after cancellation")
	}
	// Transport may detach the dial context from the request; startup must
	// cancel and join those dials before replacing routing or DNS state.
	closeDownloads()
	select {
	case err := <-dialDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled download dial = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("download cleanup did not stop the in-flight dial")
	}
}

func TestSurgeDownloadPreservesDirectRouteMark(t *testing.T) {
	marked := false
	direct := surgeDownloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		t.Error("marked route used the default direct dialer")
		return nil, net.ErrClosed
	})
	c := surgeDownloadTestPlane(t, "dport(443) -> direct(mark: 37)", direct)
	c.markedDirectDialers.Store(uint32(37), surgeDownloadTestDialer(func(_ context.Context, network, address string) (net.Conn, error) {
		marked = true
		if network != "tcp" || address != "[2001:db8::1]:443" {
			t.Errorf("marked dial target = %s %s", network, address)
		}
		return nil, io.EOF
	}))
	_, err := surgeDownloadDialContext(c)(context.Background(), "tcp6", netip.MustParseAddrPort("[2001:db8::1]:443").String())
	if !marked || !errors.Is(err, io.EOF) {
		t.Fatalf("marked = %v, error = %v", marked, err)
	}
}

func TestSurgeDownloadDoesNotChangeOutboundAfterDialFailure(t *testing.T) {
	var calls []string
	group := func(name string) *outbound.DialerGroup {
		return surgeDownloadTestGroup(t, name, func(context.Context, string, string) (net.Conn, error) {
			calls = append(calls, name)
			return nil, io.EOF
		})
	}
	c := surgeDownloadTestPlane(t, "dport(443) -> proxy", group("direct"), group("block"), group("proxy"), group("unrelated"))
	_, err := surgeDownloadDialContext(c)(context.Background(), "tcp", "198.51.100.4:443")
	if !errors.Is(err, io.EOF) || !reflect.DeepEqual(calls, []string{"proxy"}) {
		t.Fatalf("dial error=%v, attempted outbounds=%v", err, calls)
	}
}

func TestSurgeDownloadUsesCheckedSelectorPolicy(t *testing.T) {
	var selected string
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"check.example:53", "192.0.2.53"}},
		CheckInterval:     time.Hour, CheckIntervalMax: time.Hour,
	}
	newDialer := func(name string) *dialer.Dialer {
		transport := surgeDownloadTestDialer(func(_ context.Context, network, address string) (net.Conn, error) {
			if address != "192.0.2.53:53" {
				selected = name
				return nil, io.EOF
			}
			if network != "tcp" {
				return nil, net.ErrClosed
			}
			conn, peer := net.Pipe()
			go func() {
				defer peer.Close()
				server := &dnsmessage.Conn{Conn: peer}
				message, err := server.ReadMsg()
				if err != nil {
					return
				}
				message.Response = true
				message.Answer = []dnsmessage.RR{testARecord(message.Question[0].Name, "198.51.100.1")}
				_ = server.WriteMsg(message)
			}()
			return conn, nil
		})
		return dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: transport}), option,
			&dialer.Property{Name: name, Link: "test://" + t.Name() + "/" + name}, true, "")
	}
	selector := outbound.NewDialerGroup(option, "proxy", outbound.GroupKindSelector,
		[]*dialer.Dialer{newDialer("first"), newDialer("selected")}, []*dialer.Annotation{{}, {}},
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 1}, nil)
	t.Cleanup(func() { _ = selector.Close() })
	start := make(chan struct{})
	ready, err := selector.StartConnectivityChecks(start)
	if err != nil {
		t.Fatal(err)
	}
	close(start)
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("selector did not finish its initial connectivity check")
	}
	unexpected := func(context.Context, string, string) (net.Conn, error) {
		t.Error("healthy selector fell back to another outbound")
		return nil, net.ErrClosed
	}
	c := surgeDownloadTestPlane(t, "dport(443) -> proxy",
		surgeDownloadTestGroup(t, "direct", unexpected), surgeDownloadTestGroup(t, "block", unexpected), selector)
	_, err = surgeDownloadDialContext(c)(context.Background(), "tcp4", "198.51.100.4:443")
	if !errors.Is(err, io.EOF) || selected != "selected" {
		t.Fatalf("selected dialer = %q, error = %v", selected, err)
	}
}

func TestSurgeDownloadDNSDoesNotPublishBeforeActivation(t *testing.T) {
	direct := surgeDownloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		t.Error("DNS fixture unexpectedly dialed the network")
		return nil, net.ErrClosed
	})
	c := surgeDownloadTestPlane(t, "domain(full: raw.example, full: 192.0.2.53) -> direct", direct)
	registry, kernel := newTestRegistry(16, 16, time.Second)
	c.core.domainRegistry = registry
	queries := 0
	configuration := attachSurgeDownloadTestDNS(t, c, "test", "accept", func(message *dnsmessage.Msg) {
		queries++
		message.Response = true
		message.Answer = []dnsmessage.RR{testARecord(message.Question[0].Name, "198.51.100.4")}
	})
	addresses, err := c.resolveSurgeDownload(context.Background(), "raw.example", dnsmessage.TypeA, bpfRoutingResult{})
	if err != nil || !reflect.DeepEqual(addresses, []netip.Addr{netip.MustParseAddr("198.51.100.4")}) || queries != 1 {
		t.Fatalf("bootstrap DNS addresses = %v, queries = %d, error = %v", addresses, queries, err)
	}
	if registry.Size() != 0 || len(kernel.bump) != 0 {
		t.Fatal("bootstrap DNS published answers or upstreams to the shared registry")
	}
	bootstrap := c.dnsController
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := c.newDNSController(configuration, preparedRules{}, registry)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	// Keep c.dnsController pointing at the closed bootstrap controller until
	// after GetUpstream: the callback must belong to the new controller itself.
	upstream, err := final.routing.GetUpstream(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.Lookup(queryInfo{qname: "192.0.2.53.", qtype: dnsmessage.TypeA}); !reflect.DeepEqual(got, []netip.Addr{upstream.Ip4}) {
		t.Fatalf("final controller did not register its upstream: %v", got)
	}
	if !kernel.has(upstream.Ip4) {
		t.Fatal("final upstream routing bitmap was not published")
	}
	if got := registry.Lookup(queryInfo{qname: "raw.example.", qtype: dnsmessage.TypeA}); len(got) != 0 {
		t.Fatalf("bootstrap answer leaked into the final registry: %v", got)
	}
}

func TestSurgeDownloadCleanupJoinsDialsBeforeReplacingPlane(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	direct := surgeDownloadTestGroup(t, "direct", func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	})
	c := surgeDownloadTestPlane(t, "", direct)
	client, closeDownloads := newSurgeDownloadClient(c)
	defer closeDownloads()
	defer unblock()
	dial := client.Transport.(*http.Transport).DialContext
	dialDone := make(chan error, 1)
	go func() {
		_, err := dial(context.Background(), "tcp", "198.51.100.4:443")
		dialDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("download dial did not start")
	}
	closed := make(chan struct{})
	go func() {
		closeDownloads()
		close(closed)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not cancel the download dial")
	}
	select {
	case <-closed:
		t.Fatal("cleanup returned before the dial exited")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after the dial exited")
	}
	if err := <-dialDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight dial returned %v", err)
	}
	// A late Transport dial must stop before reading the old plane fields.
	c.dnsController, c.routingMatcher, c.outbounds = nil, nil, nil
	if _, err := dial(context.Background(), "tcp", "raw.example:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after cleanup returned %v", err)
	}
	if _, err := dial(context.Background(), "tcp", "198.51.100.4:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IP dial after cleanup returned %v", err)
	}
}
