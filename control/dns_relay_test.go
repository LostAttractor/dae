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
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func dnsTestRequest(t *testing.T, name string, id uint16) *plugin.DNSRequest {
	t.Helper()
	m := new(dns.Msg).SetQuestion(name, dns.TypeA)
	m.Id = id
	m.SetEdns0(1232, true)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &plugin.DNSRequest{Message: m, Wire: wire, Network: "tcp"}
}

type relayTestPlugin struct{ calls, observations int }

func (*relayTestPlugin) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }
func (p *relayTestPlugin) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, r *plugin.DNSRequest) (*plugin.DNSResponse, error) {
		p.calls++
		return next(ctx, r)
	}
}
func (p *relayTestPlugin) ObserveDNS(context.Context, *plugin.DNSRequest, *plugin.DNSResponse) {
	p.observations++
}

func TestDNSDeliveryAndMustAfterDNAT(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		must, fail, trailing bool
		want                 int
	}{
		{name: "delivered", want: 1}, {name: "failed delivery", fail: true},
		{name: "trailing bytes", trailing: true}, {name: "must after DNAT", must: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controls := "dip(192.0.2.53) -> dnat('198.51.100.53:1053')"
			if tc.must {
				controls += "\ndport(1053) -> must"
			}
			matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, controls, ""))
			registry, _ := newTestRegistry(16, time.Second)
			p := new(relayTestPlugin)
			host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "observe", Plugin: p})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			c := &ControlPlane{routingMatcher: matcher, core: &controlPlaneCore{domainRegistry: registry}, mitmHost: host}
			query := dnsTestRequest(t, "test.example.", 1)
			request, bypass, err := c.dnsRequest(query.Wire, "udp", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53"), bpfRoutingResult{CaptureFlags: captureDestination})
			if err != nil || bypass != tc.must {
				t.Fatalf("must decision: %v %v", bypass, err)
			}
			m := new(dns.Msg).SetReply(request.Message)
			m.Answer = []dns.RR{testARecord("test.example.", "203.0.113.9")}
			wire, _ := m.Pack()
			if tc.trailing {
				wire = append(wire, 0xff)
			}
			delivered := false
			err = c.processDNS(t.Context(), request, bpfRoutingResult{CaptureFlags: captureDestination}, bypass, func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) {
				return &plugin.DNSResponse{Wire: wire}, nil
			}, func(got []byte) error {
				if p.observations != 0 || registry.Usage().UserUsed != 0 {
					t.Error("published before delivery")
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
			if (err != nil) != tc.fail || !delivered || p.observations != tc.want || registry.Usage().UserUsed != tc.want {
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
		request, _, err := c.dnsRequest(query.Wire, network, netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53"), bpfRoutingResult{CaptureFlags: captureDestination})
		if err == nil || request != nil {
			t.Fatalf("%s admitted a blocked DNS destination: %+v %v", network, request, err)
		}
	}
}

func TestDNSUDPExactWireAndCancellation(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint(blocked), func(t *testing.T) {
			request := &plugin.DNSRequest{Wire: []byte{0, 1, 99}, Network: "udp", Destination: netip.MustParseAddrPort("198.51.100.53:1053")}
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
					if err != nil || !bytes.Equal(wire[:n], request.Wire) {
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
			} else if err != nil || !bytes.Equal(response.Wire, []byte{0, 1, 0xff, 99}) {
				t.Fatalf("response changed: %+v %v", response, err)
			}
			<-peerDone
			if dials.Load() != 1 {
				t.Fatal("core retried UDP")
			}
		})
	}
}

func TestDNSUDPReplyRestoresOriginalDestination(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	original, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 53)})
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	src, dst := client.LocalAddr().(*net.UDPAddr).AddrPort(), original.LocalAddr().(*net.UDPAddr).AddrPort()
	// Supply an already-open reply socket to exercise delivery without creating
	// the daemon's network namespace. Kernel port-53 admission is tested separately.
	pool := DefaultAnyfromPool
	DefaultAnyfromPool = NewAnyfromPool()
	DefaultAnyfromPool.pool[dst] = &Anyfrom{UDPConn: original, idleTTL: time.Second}
	defer func() { DefaultAnyfromPool = pool }()
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
	c.handleDNSUDP(wire, src, dst, bpfRoutingResult{CaptureFlags: captureDestination})
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, from, err := client.ReadFromUDPAddrPort(buffer)
	if err != nil || from != dst || !bytes.Equal(buffer[:n], answer) {
		t.Fatalf("reply source=%s want=%s bytes=%x error=%v", from, dst, buffer[:n], err)
	}
	<-upstreamDone
}

func TestDNSStreamTransferOrdering(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	continuation := make(chan []byte, 2)
	stream := newDNSStream(conn, func(wire []byte) error { continuation <- wire; return nil }, func() {})
	defer stream.close()
	request := dnsTestRequest(t, "zone.example.", 42)
	request.Message.Question[0].Qtype = dns.TypeAXFR
	request.Wire, _ = request.Message.Pack()
	first := new(dns.Msg).SetReply(request.Message)
	firstWire, _ := first.Pack()
	last := first.Copy()
	last.Question = nil
	lastWire, _ := last.Pack()
	go func() {
		if _, err := readDNSFrame(peer); err != nil {
			return
		}
		_ = writeDNSFrame(peer, firstWire)
		_ = writeDNSFrame(peer, lastWire)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response, err := stream.exchange(ctx, request)
	if err != nil || !bytes.Equal(response.Wire, firstWire) {
		t.Fatalf("first frame: %+v %v", response, err)
	}
	select {
	case <-continuation:
		t.Fatal("continuation overtook first delivery")
	default:
	}
	cancel() // The relay cancels the operation only after first-frame delivery.
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
				requests[i], err = readDNSFrame(server)
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
				_ = writeDNSFrame(&frame, wire)
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
		done <- plane.serveDNSTCP(accepted, netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("192.0.2.53:53"), bpfRoutingResult{CaptureFlags: 8})
	}()
	for i := range count {
		if err := writeDNSFrame(client, dnsTestRequest(t, fmt.Sprintf("q%d.example.", i), uint16(i)).Wire); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint16]bool)
	for range count {
		wire, err := readDNSFrame(client)
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
	stream := newDNSStream(conn, func([]byte) error { return nil }, func() {})
	defer stream.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	request := dnsTestRequest(t, "blocked.example.", 1)
	done := make(chan error, 1)
	go func() { _, err := stream.exchange(ctx, request); done <- err }()
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
	stream := newDNSStream(conn, func([]byte) error { return errors.New("unexpected uncorrelated frame") }, func() {})
	defer stream.close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	requests := []*plugin.DNSRequest{dnsTestRequest(t, "a.example.", 7), dnsTestRequest(t, "b.example.", 7), {Wire: []byte{0, 8, 99}, Network: "tcp"}}
	go func() {
		var frames [][]byte
		for range requests {
			wire, err := readDNSFrame(peer)
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
			_ = writeDNSFrame(peer, frames[i])
		}
	}()
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Go(func() {
			response, err := stream.exchange(ctx, request)
			if err != nil {
				t.Error(err)
				return
			}
			if request.Message == nil {
				if !bytes.Equal(request.Wire, response.Wire) {
					t.Error("opaque frame changed")
				}
			} else if !dnsResponseMatches(request.Message, response.Message) {
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
	identity := bpfRoutingResult{CaptureFlags: captureDestination, Mark: 37}
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
		option, err := c.dnsDialOption(context.Background(), "udp", test.target, "", request, identity)
		if err != nil || option.Mark != test.mark || option.Outbound.Name != "proxy" || option.DialTarget != test.target {
			t.Fatalf("server route: %+v %v", option, err)
		}
	}
	identity = bpfRoutingResult{CaptureFlags: 8, Mark: 37, Outbound: uint8(consts.OutboundDirect)}
	request.OriginalDestination, request.Destination = netip.MustParseAddrPort("203.0.113.53:53"), netip.MustParseAddrPort("203.0.113.53:53")
	option, err := c.dnsDialOption(context.Background(), "udp", request.Destination.String(), "", request, identity)
	if err != nil || option.Mark != 37 || option.Outbound.Name != "direct" {
		t.Fatalf("kernel DNS decision lost: %+v %v", option, err)
	}
}
