// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func dnsTestRequest(t *testing.T, name string, id uint16) *plugin.DNSExchange {
	t.Helper()
	m := new(dns.Msg).SetQuestion(name, dns.TypeA)
	m.Id = id
	m.SetEdns0(1232, true)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &plugin.DNSExchange{DNSPacket: plugin.DNSWire(wire), Network: "tcp"}
}

func dnsTestWire(t testing.TB, packet interface{ Wire() ([]byte, error) }) []byte {
	t.Helper()
	wire, err := packet.Wire()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

type relayTestPlugin struct{ calls, observations int }

func (*relayTestPlugin) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }
func (p *relayTestPlugin) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		p.calls++
		return next(ctx, r)
	}
}
func (p *relayTestPlugin) ObserveDNS(context.Context, *plugin.DNSExchange, *plugin.DNSResponse) {
	p.observations++
}

func TestDNSRequestPreservesSourceIdentity(t *testing.T) {
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", ""))
	plane := &ControlPlane{routingMatcher: matcher}
	for _, source := range []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("[fe80::10%lan]:40000")} {
		destination := netip.MustParseAddrPort("192.0.2.53:53")
		if source.Addr().Is6() {
			destination = netip.MustParseAddrPort("[fe80::1%lan]:53")
		}
		for _, origin := range []plugin.SourceOrigin{plugin.SourceUnknown, plugin.SourceLocal, plugin.SourceLAN} {
			for _, mac := range [][6]byte{{}, {2, 0, 0, 0, 0, 1}} {
				for _, network := range []string{"udp", "tcp"} {
					request, _, err := plane.dnsRequest(nil, network, source, destination, routingResult{Mac: mac, Ifindex: 2, SourceOrigin: uint8(origin)})
					if err != nil {
						t.Fatal(err)
					}
					for _, copy := range []*plugin.DNSExchange{request, request.Copy(), request.Fork()} {
						if copy.Source != source || copy.SourceMAC != mac || copy.SourceOrigin != origin || copy.Interface != 2 {
							t.Fatalf("%s DNS identity lost: %+v", network, copy.DNSRequest)
						}
						upstream := copy.WithUpstream(plugin.DNSUpstream{Network: network, Address: destination})
						if upstream.Source != source || upstream.SourceMAC != mac || upstream.SourceOrigin != origin {
							t.Fatal("upstream lost DNS identity")
						}
					}
				}
			}
		}
	}
}

func TestDNSDeliveryAndMustAfterDNAT(t *testing.T) {
	// Domain evidence precedes delivery so the kernel has it before the client
	// connects; plugins observe only delivered answers.
	for _, tc := range []struct {
		name                       string
		must, fail, trailing, full bool
		evidence, observers        int
	}{
		{name: "delivered", evidence: 1, observers: 1}, {name: "failed delivery", fail: true, evidence: 1},
		{name: "registry full", full: true, evidence: 1, observers: 1},
		{name: "trailing bytes", trailing: true}, {name: "must after DNAT", must: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controls := "dip(192.0.2.53) -> dnat('198.51.100.53:1053')"
			if tc.must {
				controls += "\ndport(1053) -> must"
			}
			matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, controls, ""))
			registry, kernel := newTestRegistry(16, time.Second)
			ip := netip.MustParseAddr("203.0.113.9")
			if tc.full {
				registry.Upsert("original.", ip, testBitmap(0), 3600, time.Now())
				registry.memoryLimit = registry.memoryUsed
			}
			p := new(relayTestPlugin)
			host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "observe", Plugin: p})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			c := &ControlPlane{routingMatcher: matcher, core: &controlPlaneCore{domainRegistry: registry}, mitmHost: host, outbounds: dnsTestOutbounds(t)}
			query := dnsTestRequest(t, "test.example.", 1)
			request, bypass, err := c.dnsRequest(dnsTestWire(t, query), "udp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: captureDestination})
			if err != nil || bypass != tc.must {
				t.Fatalf("must decision: %v %v", bypass, err)
			}
			m := new(dns.Msg).SetReply(request.MessageCopy())
			m.Answer = []dns.RR{testARecord("test.example.", "203.0.113.9")}
			wire, _ := m.Pack()
			if tc.trailing {
				wire = append(wire, 0xff)
			}
			delivered := false
			err = c.processDNS(t.Context(), request, routingResult{CaptureFlags: captureDestination}, bypass, func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				return &plugin.DNSResponse{DNSPacket: plugin.DNSWire(wire)}, nil
			}, func(got []byte) error {
				if tc.full && (kernel.has(ip) || registry.Usage().IncompleteBuckets != 1) {
					t.Error("delivered DNS before suppressing an incomplete IP")
				}
				if p.observations != 0 || registry.Usage().UserUsed != tc.evidence {
					t.Errorf("before delivery: observers=%d evidence=%d", p.observations, registry.Usage().UserUsed)
				}
				if !bytes.Equal(got, wire) {
					t.Error("changed transparent bytes")
				}
				delivered = true
				if tc.fail {
					return net.ErrClosed
				}
				return nil
			})
			if (err != nil) != tc.fail || !delivered || p.observations != tc.observers || registry.Usage().UserUsed != tc.evidence {
				t.Fatalf("delivery=%v observers=%d registry=%d err=%v", delivered, p.observations, registry.Usage().UserUsed, err)
			}
			if tc.must && p.calls != 0 {
				t.Fatal("must entered plugin middleware")
			}
		})
	}
}

func TestDNSDNATBlockPreventsPluginAdmission(t *testing.T) {
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t,
		"dip(192.0.2.53) -> dnat('198.51.100.53:1053')", "dip(198.51.100.53) -> block"))
	c := &ControlPlane{routingMatcher: matcher}
	query := dnsTestRequest(t, "local.example.", 1)
	for _, network := range []string{"tcp", "udp"} {
		request, _, err := c.dnsRequest(dnsTestWire(t, query), network, netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: captureDestination})
		if err == nil || request != nil {
			t.Fatalf("%s admitted a blocked DNS destination: %+v %v", network, request, err)
		}
	}
}

func TestDNSUDPExactWireAndCancellation(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint(blocked), func(t *testing.T) {
			request := &plugin.DNSExchange{DNSPacket: plugin.DNSWire([]byte{0, 1, 99}), Network: "udp", Destination: netip.MustParseAddrPort("198.51.100.53:1053")}
			var dials atomic.Int32
			peerDone := make(chan struct{})
			request.DialContext = func(ctx context.Context, network, target, hostname string) (net.Conn, error) {
				dials.Add(1)
				if network != "udp" || target != request.Destination.String() {
					t.Error("lost DNAT target")
				}
				conn, peer := net.Pipe()
				go func() {
					defer close(peerDone)
					defer peer.Close()
					wire := make([]byte, 65535)
					n, err := peer.Read(wire)
					if err != nil || !bytes.Equal(wire[:n], dnsTestWire(t, request)) {
						t.Error("changed opaque UDP request")
						return
					}
					if blocked {
						_, _ = peer.Read(wire)
						return
					}
					_, _ = peer.Write([]byte{0, 1, 0xff, 99})
				}()
				return conn, nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			response, err := relayDNSUDP(ctx, request)
			if blocked {
				if err == nil {
					t.Fatal("blocked read survived cancellation")
				}
			} else if err != nil || !bytes.Equal(dnsTestWire(t, response), []byte{0, 1, 0xff, 99}) {
				t.Fatalf("response changed: %+v %v", response, err)
			}
			<-peerDone
			if dials.Load() != 1 {
				t.Fatal("core retried UDP")
			}
		})
	}
}

// The in-memory peer isolates response storage from socket and routing costs.
type dnsBufferConn struct {
	net.Conn
	payload []byte
}

func (c *dnsBufferConn) Read(p []byte) (int, error)  { return copy(p, c.payload), nil }
func (c *dnsBufferConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *dnsBufferConn) Close() error                { return nil }

func dnsBufferRequest(conn *dnsBufferConn) *plugin.DNSExchange {
	return &plugin.DNSExchange{
		Destination: netip.MustParseAddrPort("192.0.2.53:53"), Network: "udp", DNSPacket: plugin.DNSWire(make([]byte, 32)),
		DialContext: func(context.Context, string, string, string) (net.Conn, error) { return conn, nil },
	}
}

func TestDNSUDPResponseOwnership(t *testing.T) {
	conn := new(dnsBufferConn)
	request := dnsBufferRequest(conn)
	var responses []*plugin.DNSResponse
	var payloads [][]byte
	for round := range 16 {
		for _, size := range []int{0, 128, 1232, 4096, consts.MaxDnsMessageSize} {
			conn.payload = bytes.Repeat([]byte{byte(round + 1)}, size)
			response, err := relayDNSUDP(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			responses = append(responses, response)
			payloads = append(payloads, conn.payload)
		}
	}
	// Responses can outlive the exchange and later receives using the same pool.
	for i, response := range responses {
		if !bytes.Equal(dnsTestWire(t, response), payloads[i]) {
			t.Fatalf("retained response %d changed or was truncated: got %d bytes, want %d", i, len(dnsTestWire(t, response)), len(payloads[i]))
		}
	}
}

func TestDNSUDPRelayUsesRewrittenDestination(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	src, dst := netip.MustParseAddrPort("127.0.0.1:12345"), netip.MustParseAddrPort("127.0.0.53:53")
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, fmt.Sprintf("dip(127.0.0.53) -> dnat('%s')", upstream.LocalAddr()), ""))
	group := downloadTestGroup(t, "direct", func(ctx context.Context, network, target string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target)
	})
	c := &ControlPlane{dnsRelay: newDNSRelay(), routingMatcher: matcher, outbounds: []*outbound.DialerGroup{group}}
	defer c.dnsRelay.Close()
	wire := []byte{0, 1, 99}
	answer := []byte{0, 1, 99, 255}
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		_ = upstream.SetDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1024)
		n, from, err := upstream.ReadFromUDPAddrPort(buffer)
		if err != nil || !bytes.Equal(buffer[:n], wire) {
			t.Errorf("upstream bytes: %x %v", buffer[:n], err)
			return
		}
		_, _ = upstream.WriteToUDPAddrPort(answer, from)
	}()
	identity := routingResult{CaptureFlags: captureDestination}
	request, bypass, err := c.dnsRequest(wire, "udp", src, dst, identity)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var received []byte
	err = c.processDNS(ctx, request, identity, bypass, relayDNSUDP, func(wire []byte) error {
		received = bytes.Clone(wire)
		return nil
	})
	<-upstreamDone
	if err != nil || !bytes.Equal(received, answer) {
		t.Fatalf("reply bytes=%x error=%v", received, err)
	}
}

func TestDNSStreamTransferOrdering(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	continuation := make(chan []byte, 2)
	stream := newDNSStream(conn, 0, func(wire []byte) error { continuation <- wire; return nil }, func() {})
	defer stream.close()
	request := dnsTestRequest(t, "zone.example.", 42)
	query := request.MessageCopy()
	query.Question[0].Qtype = dns.TypeAXFR
	request.DNSPacket = plugin.DNSMessage(query)
	first := new(dns.Msg).SetReply(query)
	firstWire, _ := first.Pack()
	last := first.Copy()
	last.Question = nil
	lastWire, _ := last.Pack()
	go func() {
		if _, err := netutils.ReadDNSFrame(peer); err != nil {
			return
		}
		_ = netutils.WriteDNSFrame(peer, firstWire)
		_ = netutils.WriteDNSFrame(peer, lastWire)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	delivery := dnsTCPDelivery{done: make(chan struct{})}
	delivered := sync.OnceFunc(func() { close(delivery.done) })
	defer delivered()
	response, err := stream.exchange(ctx, request, &delivery)
	if err != nil || !bytes.Equal(dnsTestWire(t, response), firstWire) {
		t.Fatalf("first frame: %+v %v", response, err)
	}
	cancel() // A middleware transport deadline is not a downstream delivery.
	select {
	case <-continuation:
		t.Fatal("continuation overtook first delivery")
	case <-time.After(20 * time.Millisecond):
		// Give the independent reader a chance to forward the next frame.
		// A nonblocking check can pass even when the delivery barrier is absent.
	}
	delivery.wire = firstWire
	delivered()
	select {
	case wire := <-continuation:
		if !bytes.Equal(wire, lastWire) {
			t.Fatal("transfer continuation changed")
		}
	case <-time.After(time.Second):
		t.Fatal("transfer continuation lost")
	}
}

func TestDNSRelayTCPPipeline(t *testing.T) {
	const count = 8
	var dials atomic.Int32
	upstreamErrors := make(chan error, 1)
	group := downloadTestGroup(t, "direct", func(ctx context.Context, network, target string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || target != "192.0.2.53:53" {
			return nil, fmt.Errorf("unexpected dial %s %s", network, target)
		}
		conn, server := net.Pipe()
		go func() {
			defer server.Close()
			requests := make([][]byte, count)
			for i := range requests {
				var err error
				requests[i], err = netutils.ReadDNSFrame(server)
				if err != nil {
					upstreamErrors <- err
					return
				}
			}
			// Require all requests before any response: a sequential relay deadlocks.
			for i := count - 1; i >= 0; i-- {
				message := new(dns.Msg)
				if err := message.Unpack(requests[i]); err != nil {
					upstreamErrors <- err
					return
				}
				message.Response, message.AuthenticatedData, message.Truncated = true, true, true
				message.Answer = []dns.RR{testARecord(message.Question[0].Name, "198.51.100.9")}
				message.Answer[0].Header().Ttl = 17
				wire, _ := message.Pack()
				var frame bytes.Buffer
				_ = netutils.WriteDNSFrame(&frame, wire)
				// Fragment both the size prefix and message body.
				for _, b := range frame.Bytes() {
					if _, err := server.Write([]byte{b}); err != nil {
						upstreamErrors <- err
						return
					}
				}
			}
			upstreamErrors <- nil
		}()
		return conn, nil
	})
	plane := &ControlPlane{dnsRelay: newDNSRelay(), outbounds: []*outbound.DialerGroup{group}}
	defer plane.dnsRelay.Close()
	client, accepted := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() {
		defer accepted.Close()
		done <- plane.serveDNSTCP(accepted, netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: captureDNS})
	}()
	for i := range count {
		if err := netutils.WriteDNSFrame(client, dnsTestWire(t, dnsTestRequest(t, fmt.Sprintf("q%d.example.", i), uint16(i)))); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint16]bool)
	for range count {
		wire, err := netutils.ReadDNSFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		m := new(dns.Msg)
		if err := m.Unpack(wire); err != nil {
			t.Fatal(err)
		}
		if seen[m.Id] || !m.AuthenticatedData || !m.Truncated || m.Answer[0].Header().Ttl != 17 || m.IsEdns0().UDPSize() != 1232 {
			t.Fatalf("relay changed response: %s", m)
		}
		seen[m.Id] = true
	}
	if err := <-upstreamErrors; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP relay did not drain")
	}
	if dials.Load() != 1 {
		t.Fatalf("relay reconnected %d times", dials.Load())
	}
}

func TestDNSStreamCancellationInterruptsBlockedWrite(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	stream := newDNSStream(conn, 0, func([]byte) error { return nil }, func() {})
	defer stream.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	request := dnsTestRequest(t, "blocked.example.", 1)
	done := make(chan error, 1)
	go func() { _, err := stream.exchange(ctx, request, nil); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt write")
	}
}

func TestDNSStreamRepeatedIDAndOpaqueFrames(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	stream := newDNSStream(conn, 0, func([]byte) error { return errors.New("unexpected uncorrelated frame") }, func() {})
	defer stream.close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	requests := []*plugin.DNSExchange{dnsTestRequest(t, "a.example.", 7), dnsTestRequest(t, "b.example.", 7), {DNSPacket: plugin.DNSWire([]byte{0, 8, 99}), Network: "tcp"}}
	go func() {
		var frames [][]byte
		for range requests {
			wire, err := netutils.ReadDNSFrame(peer)
			if err != nil {
				return
			}
			frames = append(frames, wire)
		}
		for i := len(frames) - 1; i >= 0; i-- {
			m := new(dns.Msg)
			if m.Unpack(frames[i]) == nil {
				m.Response = true
				frames[i], _ = m.Pack()
			}
			_ = netutils.WriteDNSFrame(peer, frames[i])
		}
	}()
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Go(func() {
			response, err := stream.exchange(ctx, request, nil)
			if err != nil {
				t.Error(err)
				return
			}
			if request.MessageCopy() == nil {
				if !bytes.Equal(dnsTestWire(t, request), dnsTestWire(t, response)) {
					t.Error("opaque frame changed")
				}
			} else if !dnsResponseMatches(request.MessageCopy(), response.MessageCopy()) {
				t.Error("repeated ID matched the wrong question")
			}
		})
	}
	wg.Wait()
}

func TestDNSDialPreservesIngressAndReroutesAssignedServer(t *testing.T) {
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	groups := []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused)}
	prepared := prepareFlowRulesForTest(t, "dip(192.0.2.53) -> dnat('198.51.100.53:1053')", "dip(198.51.100.53) -> proxy(mark:91)\ndport(5353) -> proxy(mark:73)")
	matcher, _ := routingMatcherForTest(t, prepared)
	c := &ControlPlane{routingMatcher: matcher, outbounds: groups}
	src, dst := netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53")
	identity := routingResult{CaptureFlags: captureDestination, Mark: 37}
	request, _, err := c.dnsRequest([]byte{0, 1, 2}, "udp", src, dst, identity)
	if err != nil {
		t.Fatal(err)
	}
	if request.Destination.String() != "198.51.100.53:1053" || request.OriginalDestination != dst || request.Source != src {
		t.Fatalf("DNAT provenance lost: %+v", request)
	}
	for _, test := range []struct {
		target string
		mark   uint32
	}{{request.Destination.String(), 91}, {"203.0.113.53:5353", 73}} {
		option, err := c.dnsUpstreamOption(context.Background(), "udp", test.target, "", request, identity)
		if err != nil || option.Mark != test.mark || option.Outbound.Name != "proxy" || option.DialTarget != test.target {
			t.Fatalf("server route: %+v %v", option, err)
		}
	}
	identity = routingResult{CaptureFlags: captureDNS, Mark: 37, Outbound: uint8(consts.OutboundDirect)}
	request.OriginalDestination, request.Destination = netip.MustParseAddrPort("203.0.113.53:53"), netip.MustParseAddrPort("203.0.113.53:53")
	option, err := c.dnsUpstreamOption(context.Background(), "udp", request.Destination.String(), "", request, identity)
	if err != nil || option.Mark != 37 || option.Outbound.Name != "direct" {
		t.Fatalf("kernel DNS decision lost: %+v %v", option, err)
	}
}
