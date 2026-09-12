// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	dns "github.com/miekg/dns"
)

func resolverTestServer(t *testing.T, truncateUDP bool) netip.AddrPort {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg).SetReply(request)
		response.RecursionAvailable = true
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP && truncateUDP {
			response.Truncated = true
		} else {
			ip := net.IPv4(192, 0, 2, 80)
			if request.Question[0].Name == "proxy-bootstrap.example." {
				ip = net.IPv4(127, 0, 0, 1)
			}
			if request.Question[0].Qtype == dns.TypeA {
				response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}}
			}
		}
		_ = w.WriteMsg(response)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	return netip.MustParseAddrPort(tcp.Addr().String())
}

func testInternalResolver() *InternalResolver {
	return newInternalResolver(netip.AddrPort{}, new(net.Dialer).DialContext)
}

func lookupResolverTest(t *testing.T, resolver *net.Resolver) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := resolver.LookupNetIP(ctx, "ip4", "resolver-test.example.")
	if err != nil || !slices.Equal(ips, []netip.Addr{netip.MustParseAddr("192.0.2.80")}) {
		t.Fatalf("lookup = %v, %v", ips, err)
	}
}

func TestInternalResolverBootstrapAndRoutedTCPRetry(t *testing.T) {
	server := resolverTestServer(t, true)
	r := testInternalResolver()
	r.Configure(server, nil)
	lookupResolverTest(t, r.Resolver)
	var networks []string
	r.SetRoute(func(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
		if address != server {
			t.Errorf("routed server = %v, want %v", address, server)
		}
		networks = append(networks, network)
		conn, err := new(net.Dialer).DialContext(ctx, network, address.String())
		// Reproduce the capability-erasing accounting/outbound wrapper.
		return struct{ net.Conn }{conn}, err
	})
	lookupResolverTest(t, r.Resolver)
	if !slices.Equal(networks, []string{"udp", "tcp"}) {
		t.Fatalf("Go UDP/TCP retry changed: %v", networks)
	}
}

func TestInternalResolverBootstrapHasIndependentLookup(t *testing.T) {
	server := resolverTestServer(t, false)
	r := testInternalResolver()
	r.Configure(server, func(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
		// Resolve the SAME hostname while its routed lookup is pending. Sharing
		// a resolver/singleflight group here would deadlock proxy bootstrapping.
		if _, err := r.Bootstrap.LookupNetIP(ctx, "ip4", "resolver-test.example."); err != nil {
			return nil, err
		}
		return new(net.Dialer).DialContext(ctx, network, address.String())
	})
	lookupResolverTest(t, r.Resolver)
}

func TestInternalResolverBootstrapsProxyWhenRouteIsUnavailable(t *testing.T) {
	server := resolverTestServer(t, false)
	r := testInternalResolver()
	r.Configure(server, func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		t.Error("proxy establishment recursively entered routed DNS")
		return nil, errors.New("proxy not ready")
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	dialer := direct.NewDirectDialer(direct.Option{Resolver: r.Bootstrap})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("proxy-bootstrap.example", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()

	udp, err := net.ListenPacket("udp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	// The same injected bootstrap resolver serves connected UDP and packet
	// sockets. Both must preserve datagram boundaries and native socket access.
	for _, mode := range []string{"connected", "packet"} {
		t.Run(mode, func(t *testing.T) {
			address := netproxy.NewAddr("udp", net.JoinHostPort("proxy-bootstrap.example", port))
			var conn net.Conn
			var socket syscall.Conn
			if mode == "connected" {
				conn, err = dialer.DialContext(ctx, "udp", address.String())
				if err != nil {
					t.Fatal(err)
				}
				socket = conn.(syscall.Conn)
			} else {
				packet, err := dialer.ListenPacket(ctx, address.String())
				if err != nil {
					t.Fatal(err)
				}
				conn = &netproxy.BindPacketConn{PacketConn: packet, Address: address}
				socket = packet.(syscall.Conn)
			}
			defer conn.Close()
			if _, err := socket.SyscallConn(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			_ = udp.SetDeadline(deadline)
			_ = conn.SetDeadline(deadline)
			for _, payload := range []string{"first", "second datagram"} {
				if _, err := conn.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 64)
				n, from, err := udp.ReadFrom(buffer)
				if err != nil || string(buffer[:n]) != payload {
					t.Fatalf("UDP payload = %q, error=%v", buffer[:n], err)
				}
				if _, err := udp.WriteTo(buffer[:n], from); err != nil {
					t.Fatal(err)
				}
				n, err = conn.Read(buffer)
				if err != nil || string(buffer[:n]) != payload {
					t.Fatalf("UDP reply = %q, error=%v", buffer[:n], err)
				}
			}
		})
	}
}

func TestInternalResolverHandoffPreservesInflightPolicy(t *testing.T) {
	r := testInternalResolver()
	a, b := netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("192.0.2.2:1053")
	oldResult, newResult := errors.New("old route"), errors.New("new route")
	entered, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	r.Configure(a, func(_ context.Context, _ string, server netip.AddrPort) (net.Conn, error) {
		if server != a {
			t.Errorf("old route got %s", server)
		}
		close(entered)
		<-release
		return nil, oldResult
	})
	go func() {
		_, err := r.Resolver.Dial(context.Background(), "udp", "127.0.0.53:53")
		result <- err
	}()
	<-entered
	r.direct = func(_ context.Context, _ string, address string) (net.Conn, error) {
		if address != b.String() {
			t.Errorf("handoff bootstrap got %s", address)
		}
		return nil, newResult
	}
	r.Configure(b, nil)
	_, err := r.Resolver.Dial(context.Background(), "udp", "127.0.0.53:53")
	if err != newResult {
		t.Errorf("handoff did not use direct bootstrap: %v", err)
	}
	r.SetRoute(func(_ context.Context, _ string, server netip.AddrPort) (net.Conn, error) {
		if server != b {
			t.Errorf("new route got %s", server)
		}
		return nil, newResult
	})
	_, err = r.Resolver.Dial(context.Background(), "udp", "127.0.0.53:53")
	if err != newResult {
		t.Errorf("new route result: %v", err)
	}
	close(release)
	if err := <-result; err != oldResult {
		t.Fatalf("in-flight old route changed: %v", err)
	}
}

func TestInternalResolverSystemDefaultAndRoutingFailure(t *testing.T) {
	r := testInternalResolver()
	want := errors.New("route blocked")
	directCalls, routeCalls := 0, 0
	r.direct = func(_ context.Context, network, address string) (net.Conn, error) {
		directCalls++
		if network != "udp" || address != "127.0.0.53:53" {
			t.Errorf("changed standard-library server: %s %s", network, address)
		}
		return nil, want
	}
	route := func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		routeCalls++
		return nil, want
	}
	r.SetRoute(route)
	_, _ = r.Resolver.Dial(context.Background(), "udp", "127.0.0.53:53")
	if directCalls != 1 || routeCalls != 0 {
		t.Fatal("omitted setting did not preserve system resolution")
	}
	r.Configure(netip.MustParseAddrPort("192.0.2.53:1053"), route)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := r.Resolver.LookupNetIP(ctx, "ip4", "resolver-test.example."); err == nil {
		t.Fatal("routing error ignored")
	}
	if directCalls != 1 || routeCalls == 0 {
		t.Fatal("failed routed lookup escaped through direct/system DNS")
	}
}

func TestInternalResolverConcurrentPolicySwitch(t *testing.T) {
	r := testInternalResolver()
	a, b := netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("192.0.2.2:1053")
	stop := errors.New("test dial")
	route := func(server netip.AddrPort) ResolverDialContext {
		return func(_ context.Context, _ string, got netip.AddrPort) (net.Conn, error) {
			if got != server {
				t.Errorf("mixed server/route snapshot: %s != %s", got, server)
			}
			return nil, stop
		}
	}
	r.Configure(a, route(a))
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			r.Configure(b, route(b))
			r.Configure(a, route(a))
		}
	})
	for range 4 {
		wg.Go(func() {
			for range 100 {
				_, _ = r.Resolver.Dial(context.Background(), "udp", "127.0.0.53:53")
			}
		})
	}
	wg.Wait()
}
