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

type downloadTestDialer func(context.Context, string, string) (net.Conn, error)

func (d downloadTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d(ctx, network, address)
}

func (downloadTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func downloadTestGroup(t *testing.T, name string, dial downloadTestDialer) *outbound.DialerGroup {
	t.Helper()
	option := &dialer.GlobalOption{}
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: dial}), option,
		&dialer.Property{Name: name, Link: "test://" + t.Name() + "/" + name}, false, "")
	group := outbound.NewDialerGroup(option, name, outbound.GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = group.Close() })
	return group
}

func downloadTestPlane(t *testing.T, rules string, groups ...*outbound.DialerGroup) *ControlPlane {
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
	builder, err := compileTestRouting(preparedRules{routing: &configuration.Routing}, ids, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	return &ControlPlane{core: &controlPlaneCore{}, outbounds: groups, routingMatcher: matcher}
}

type downloadTestDNS func(*dnsmessage.Msg)

func attachDownloadTestDNS(t *testing.T, c *ControlPlane, request, response string, answer downloadTestDNS) {
	t.Helper()
	previous := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = previous })
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, peer := net.Pipe()
		go func() {
			defer peer.Close()
			server := &dnsmessage.Conn{Conn: peer}
			message, err := server.ReadMsg()
			if err != nil {
				return
			}
			answer(message)
			message.Response = true
			message.RecursionAvailable = true
			_ = server.WriteMsg(message)
		}()
		return conn, nil
	}}
}

func TestMITMDownloadRoutesResolvedDestination(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "ip", true: "domain"}[override], func(t *testing.T) {
			var calls []string
			group := func(name string) *outbound.DialerGroup {
				return downloadTestGroup(t, name, func(ctx context.Context, network, address string) (net.Conn, error) {
					calls = append(calls, name+" "+network+" "+address)
					if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > consts.DefaultDialTimeout {
						t.Error("download dial has no bounded timeout")
					}
					conn, peer := net.Pipe()
					_ = peer.Close()
					return conn, nil
				})
			}
			c := downloadTestPlane(t, "domain(full: raw.example) && dip(198.51.100.0/24) && dport(443) -> proxy", group("direct"), group("block"), group("proxy"), group("unused"))
			c.dialTargetOverride = override
			attachDownloadTestDNS(t, c, "test", "accept", func(message *dnsmessage.Msg) {
				question := message.Question[0]
				if question.Name != "raw.example." || question.Qtype != dnsmessage.TypeA {
					t.Errorf("unexpected DNS query: %+v", question)
				}
				message.Response = true
				message.Answer = []dnsmessage.RR{
					&dnsmessage.CNAME{Hdr: dnsmessage.RR_Header{Name: question.Name, Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 60}, Target: "edge.example."},
					testARecord("edge.example.", "198.51.100.4"),
				}
			})
			conn, err := mitmClientDialContext(c)(context.Background(), "tcp", "raw.example:443")
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

func TestMITMDownloadHonorsSystemDNSFailure(t *testing.T) {
	c := downloadTestPlane(t, "", downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		t.Error("unresolved download reached a TCP dialer")
		return nil, net.ErrClosed
	}))
	attachDownloadTestDNS(t, c, "", "", func(message *dnsmessage.Msg) { message.Rcode = dnsmessage.RcodeNameError })
	if _, err := mitmClientDialContext(c)(context.Background(), "tcp4", "raw.example:443"); err == nil {
		t.Fatal("system resolver failure ignored")
	}
}

func TestMITMDownloadHonorsBlockAndConnectivityFallback(t *testing.T) {
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
			direct := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
				directCalls++
				conn, peer := net.Pipe()
				_ = peer.Close()
				return conn, nil
			})
			unexpected := func(context.Context, string, string) (net.Conn, error) {
				t.Error("download dialed a blocked or unhealthy path")
				return nil, net.ErrClosed
			}
			block := downloadTestGroup(t, "block", unexpected)
			option := &dialer.GlobalOption{}
			d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: downloadTestDialer(unexpected)}), option,
				&dialer.Property{Name: "unavailable"}, true, "")
			unavailable := outbound.NewDialerGroup(option, "unavailable", outbound.GroupKindSelector,
				[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
			t.Cleanup(func() { _ = unavailable.Close() })
			c := downloadTestPlane(t, test.rules, direct, block, unavailable)
			c.noConnectivityOutbound = test.fallback
			c.routingMatcher.outboundUsable = func(index uint8, _ consts.L4ProtoType, version consts.IpVersionType) bool {
				_, err := c.outbounds[index].Select(&common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: version.ToIpVersionStr()})
				return err == nil
			}
			conn, err := mitmClientDialContext(c)(context.Background(), "tcp", "198.51.100.4:443")
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

func TestMITMDownloadRoutesRedirectDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://203.0.113.8/resource.json", http.StatusFound)
	}))
	defer server.Close()
	calls := 0
	direct := downloadTestGroup(t, "direct", func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		return new(net.Dialer).DialContext(ctx, network, address)
	})
	block := downloadTestGroup(t, "block", func(context.Context, string, string) (net.Conn, error) {
		t.Error("redirect bypassed the block rule")
		return nil, net.ErrClosed
	})
	c := downloadTestPlane(t, "dip(203.0.113.8) -> block", direct, block)
	client, closeDownloads := newMITMClient(c, 30*time.Second)
	defer closeDownloads()
	_, err := client.Get(server.URL)
	if err == nil || !strings.Contains(err.Error(), "blocked by routing") || calls != 1 {
		t.Fatalf("redirect error = %v, direct calls = %d", err, calls)
	}
}

func TestMITMDownloadStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	direct := downloadTestGroup(t, "direct", func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	client, closeDownloads := newMITMClient(downloadTestPlane(t, "", direct), 30*time.Second)
	defer closeDownloads()
	transport := client.Transport.(*http.Transport)
	dial := transport.DialContext
	dialDone := make(chan error, 1)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		dialDone <- err
		return conn, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://198.51.100.4/resource.json", nil)
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

func TestMITMDownloadPreservesDirectRouteMark(t *testing.T) {
	marked := false
	direct := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		t.Error("marked route used the default direct dialer")
		return nil, net.ErrClosed
	})
	c := downloadTestPlane(t, "dport(443) -> direct(mark: 37)", direct)
	c.markedDirectDialers.Store(uint32(37), downloadTestDialer(func(_ context.Context, network, address string) (net.Conn, error) {
		marked = true
		if network != "tcp" || address != "[2001:db8::1]:443" {
			t.Errorf("marked dial target = %s %s", network, address)
		}
		return nil, io.EOF
	}))
	_, err := mitmClientDialContext(c)(context.Background(), "tcp6", netip.MustParseAddrPort("[2001:db8::1]:443").String())
	if !marked || !errors.Is(err, io.EOF) {
		t.Fatalf("marked = %v, error = %v", marked, err)
	}
}

func TestMITMDownloadDoesNotChangeOutboundAfterDialFailure(t *testing.T) {
	var calls []string
	group := func(name string) *outbound.DialerGroup {
		return downloadTestGroup(t, name, func(context.Context, string, string) (net.Conn, error) {
			calls = append(calls, name)
			return nil, io.EOF
		})
	}
	c := downloadTestPlane(t, "dport(443) -> proxy", group("direct"), group("block"), group("proxy"), group("unrelated"))
	_, err := mitmClientDialContext(c)(context.Background(), "tcp", "198.51.100.4:443")
	if !errors.Is(err, io.EOF) || !reflect.DeepEqual(calls, []string{"proxy"}) {
		t.Fatalf("dial error=%v, attempted outbounds=%v", err, calls)
	}
}

func TestMITMDownloadUsesCheckedSelectorPolicy(t *testing.T) {
	var selected string
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"check.example:53", "192.0.2.53"}},
		CheckInterval:     time.Hour, CheckIntervalMax: time.Hour,
	}
	newDialer := func(name string) *dialer.Dialer {
		transport := downloadTestDialer(func(_ context.Context, network, address string) (net.Conn, error) {
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
	c := downloadTestPlane(t, "dport(443) -> proxy",
		downloadTestGroup(t, "direct", unexpected), downloadTestGroup(t, "block", unexpected), selector)
	_, err = mitmClientDialContext(c)(context.Background(), "tcp4", "198.51.100.4:443")
	if !errors.Is(err, io.EOF) || selected != "selected" {
		t.Fatalf("selected dialer = %q, error = %v", selected, err)
	}
}

func TestMITMDownloadDNSDoesNotPublishBeforeActivation(t *testing.T) {
	direct := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		t.Error("DNS fixture unexpectedly dialed the network")
		return nil, net.ErrClosed
	})
	c := downloadTestPlane(t, "domain(full: raw.example, full: 192.0.2.53) -> direct", direct)
	registry, kernel := newTestRegistry(16, time.Second)
	c.core.domainRegistry = registry
	queries := 0
	attachDownloadTestDNS(t, c, "test", "accept", func(message *dnsmessage.Msg) {
		queries++
		message.Response = true
		message.Answer = []dnsmessage.RR{testARecord(message.Question[0].Name, "198.51.100.4")}
	})
	addresses, err := c.resolveHTTPAddresses(context.Background(), "raw.example", dnsmessage.TypeA, netip.AddrPort{}, routingResult{})
	if err != nil || !reflect.DeepEqual(addresses, []netip.Addr{netip.MustParseAddr("198.51.100.4")}) || queries != 1 {
		t.Fatalf("bootstrap DNS addresses = %v, queries = %d, error = %v", addresses, queries, err)
	}
	if registry.Size() != 0 || len(kernel.bump) != 0 {
		t.Fatal("bootstrap DNS published answers or upstreams to the shared registry")
	}
}

func TestMITMDownloadCleanupJoinsDialsBeforeReplacingPlane(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	direct := downloadTestGroup(t, "direct", func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	})
	c := downloadTestPlane(t, "", direct)
	client, closeDownloads := newMITMClient(c, 30*time.Second)
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
	c.dnsRelay, c.routingMatcher, c.outbounds = nil, nil, nil
	if _, err := dial(context.Background(), "tcp", "raw.example:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after cleanup returned %v", err)
	}
	if _, err := dial(context.Background(), "tcp", "198.51.100.4:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IP dial after cleanup returned %v", err)
	}
}
