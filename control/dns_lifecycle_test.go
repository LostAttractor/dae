// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func TestDNSStreamHeaderOnlyErrors(t *testing.T) {
	for _, rcode := range []int{dns.RcodeFormatError, dns.RcodeNotImplemented, dns.RcodeRefused} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			conn, peer := net.Pipe()
			defer peer.Close()
			stream := newDNSStream(conn, 0, func([]byte) error { t.Error("correlated error treated as unsolicited"); return nil }, func() {})
			defer stream.close()
			q := dnsTestRequest(t, "error.example.", 123)
			go func() {
				for range 2 {
					wire, err := netutils.ReadDNSFrame(peer)
					if err != nil {
						return
					}
					request := unpackDNSMessage(wire)
					response := new(dns.Msg).SetReply(request)
					if request.Id == q.MessageCopy().Id {
						response.Question, response.Rcode = nil, rcode
					}
					wire, _ = response.Pack()
					if netutils.WriteDNSFrame(peer, wire) != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			response, err := stream.exchange(ctx, q, nil)
			if err != nil || response.MessageCopy().Rcode != rcode || len(response.MessageCopy().Question) != 0 {
				t.Fatalf("header-only response was lost/rewritten: %+v %v", response, err)
			}
			if dnsResponseMatches(q.MessageCopy(), response.MessageCopy()) {
				t.Fatal("header-only error became evidence")
			}
			if _, err := stream.exchange(ctx, dnsTestRequest(t, "next.example.", 124), nil); err != nil {
				t.Fatalf("error response poisoned shared connection: %v", err)
			}
		})
	}
}

func TestDNSStreamHeaderOnlyErrorWithRepeatedID(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	unsolicited := make(chan struct{}, 1)
	stream := newDNSStream(conn, 0, func([]byte) error { unsolicited <- struct{}{}; return nil }, func() {})
	defer stream.close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	finished := make(chan error, 2)
	for _, name := range []string{"one.example.", "two.example."} {
		go func() { _, err := stream.exchange(ctx, dnsTestRequest(t, name, 7), nil); finished <- err }()
	}
	requests := make([]*dns.Msg, 2)
	for i := range requests {
		wire, err := netutils.ReadDNSFrame(peer)
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = unpackDNSMessage(wire)
	}
	bad := new(dns.Msg).SetReply(requests[0])
	bad.Question, bad.Rcode = nil, dns.RcodeFormatError
	wire, _ := bad.Pack()
	if err := netutils.WriteDNSFrame(peer, wire); err != nil {
		t.Fatal(err)
	}
	<-unsolicited
	select {
	case err := <-finished:
		t.Fatalf("ambiguous error completed a request: %v", err)
	default:
	}
	for _, request := range requests {
		wire, _ := new(dns.Msg).SetReply(request).Pack()
		if err := netutils.WriteDNSFrame(peer, wire); err != nil {
			t.Fatal(err)
		}
	}
	for range requests {
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
}

// Scale only the client's idle budget, so full TCP relay tests can exercise
// response progress and idle expiry without sleeping for thirty seconds.
type shortDNSIdleConn struct{ net.Conn }

func (c shortDNSIdleConn) SetReadDeadline(deadline time.Time) error {
	return c.Conn.SetReadDeadline(time.Now().Add(time.Until(deadline) / 100))
}

func dnsTCPTestClient(t *testing.T, host *mitm.Host, server func(net.Conn)) net.Conn {
	t.Helper()
	client, accepted := net.Pipe()
	serveTestDNSTCP(t, client, accepted, host, server)
	return client
}

func serveTestDNSTCP(t *testing.T, client, accepted net.Conn, host *mitm.Host, server func(net.Conn)) {
	t.Helper()
	group := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		conn, peer := net.Pipe()
		go func() { defer peer.Close(); server(peer) }()
		return conn, nil
	})
	c := &ControlPlane{dnsRelay: newDNSRelay(), outbounds: []*outbound.DialerGroup{group}, mitmHost: host}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer accepted.Close()
		_ = c.serveDNSTCP(shortDNSIdleConn{accepted}, netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: captureDNS})
	}()
	t.Cleanup(func() { client.Close(); c.dnsRelay.Close(); <-done })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
}

func TestDNSTCPUpstreamEOFDrainsLastResponse(t *testing.T) {
	client := dnsTCPTestClient(t, nil, func(peer net.Conn) {
		wire, err := netutils.ReadDNSFrame(peer)
		if err != nil {
			return
		}
		message := unpackDNSMessage(wire)
		message.Response = true
		wire, _ = message.Pack()
		_ = netutils.WriteDNSFrame(peer, wire)
	})
	query := dnsTestRequest(t, "eof.example.", 1)
	if err := netutils.WriteDNSFrame(client, dnsTestWire(t, query)); err != nil {
		t.Fatal(err)
	}
	// Give the upstream time to close while delivery is blocked on this client.
	time.Sleep(20 * time.Millisecond)
	wire, err := netutils.ReadDNSFrame(client)
	if err != nil || !dnsResponseMatches(query.MessageCopy(), unpackDNSMessage(wire)) {
		t.Fatalf("lost last response: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := netutils.ReadDNSFrame(client); !errors.Is(err, io.EOF) {
		t.Fatalf("upstream EOF not propagated: %v", err)
	}
}

func TestDNSTCPActiveTransferAndIdleExpiry(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeAXFR, dns.TypeIXFR} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			const frames = 60
			client := dnsTCPTestClient(t, nil, func(peer net.Conn) {
				wire, err := netutils.ReadDNSFrame(peer)
				if err != nil {
					return
				}
				message := unpackDNSMessage(wire)
				message.Response = true
				for range frames {
					wire, _ = message.Pack()
					if netutils.WriteDNSFrame(peer, wire) != nil {
						return
					}
					message.Question = nil
					time.Sleep(10 * time.Millisecond)
				}
				// Remain open and idle: the relay must still collect idle clients.
				_, _ = peer.Read(make([]byte, 1))
			})
			query := dnsTestRequest(t, "zone.example.", 1)
			message := query.MessageCopy()
			message.Question[0].Qtype = qtype
			query.DNSPacket = plugin.DNSMessage(message)
			if err := netutils.WriteDNSFrame(client, dnsTestWire(t, query)); err != nil {
				t.Fatal(err)
			}
			for i := range frames {
				if _, err := netutils.ReadDNSFrame(client); err != nil {
					t.Fatalf("active transfer stopped at frame %d: %v", i, err)
				}
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := netutils.ReadDNSFrame(client); !errors.Is(err, io.EOF) {
				t.Fatalf("idle connection not collected: %v", err)
			}
		})
	}
}

type dnsTestMiddleware func(plugin.DNSHandler) plugin.DNSHandler

func (dnsTestMiddleware) Plan() plugin.Plan                                  { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }
func (p dnsTestMiddleware) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler { return p(next) }

func TestDNSTCPTransferIsolatedFromRetainedStreams(t *testing.T) {
	for _, occupied := range []int{0, 16} {
		t.Run(fmt.Sprintf("retained=%d", occupied), func(t *testing.T) {
			testDNSTCPTransferIsolation(t, occupied)
		})
	}
}

func testDNSTCPTransferIsolation(t *testing.T, occupied int) {
	t.Helper()
	for _, qtype := range []uint16{dns.TypeAXFR, dns.TypeIXFR} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			perName := dnsTestMiddleware(func(next plugin.DNSHandler) plugin.DNSHandler {
				return func(ctx context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
					q, _ := r.Question()
					r.RouteUpstream, r.Egress = nil, q.Name
					answer, err := next(ctx, r)
					if err == nil && q.Name == "filtered.example." {
						answer = &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetRcode(r.MessageCopy(), dns.RcodeRefused))}
					}
					return answer, err
				}
			})
			host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "egress", Plugin: perName})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = host.Close() })
			client := dnsTCPTestClient(t, host, func(peer net.Conn) {
				wire, err := netutils.ReadDNSFrame(peer)
				if err != nil {
					return
				}
				query := unpackDNSMessage(wire)
				answer := new(dns.Msg).SetReply(query)
				if query.Question[0].Qtype == qtype {
					answer.Answer = []dns.RR{dnsTransferTestSOA(query.Question[0].Name, 2)}
				}
				wire, _ = answer.Pack()
				if netutils.WriteDNSFrame(peer, wire) != nil {
					return
				}
				if query.Question[0].Qtype == qtype {
					answer.Question = nil
					wire, _ = answer.Pack()
					_ = netutils.WriteDNSFrame(peer, wire)
					return
				}
				_, _ = peer.Read(make([]byte, 1))
			})
			for i := range occupied + 1 {
				q := dnsTestRequest(t, fmt.Sprintf("zone%d.example.", i), uint16(i))
				if i == occupied {
					m := q.MessageCopy()
					m.Question[0].Qtype = qtype
					q.DNSPacket = plugin.DNSMessage(m)
				}
				if err := netutils.WriteDNSFrame(client, dnsTestWire(t, q)); err != nil {
					t.Fatal(err)
				}
				wire, err := netutils.ReadDNSFrame(client)
				if err != nil || !dnsResponseMatches(q.MessageCopy(), unpackDNSMessage(wire)) {
					t.Fatalf("egress %d: lost first response: %v", i, err)
				}
			}
			wire, err := netutils.ReadDNSFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			last := unpackDNSMessage(wire)
			if last.Id != uint16(occupied) || len(last.Question) != 0 || len(last.Answer) != 1 || last.Answer[0].Header().Rrtype != dns.TypeSOA {
				t.Fatalf("unexpected continuation: %v", last)
			}
			filtered := new(dns.Msg).SetQuestion("filtered.example.", qtype)
			if err := netutils.WriteDNSFrame(client, dnsTestWire(t, plugin.DNSMessage(filtered))); err != nil {
				t.Fatal(err)
			}
			wire, err = netutils.ReadDNSFrame(client)
			if err != nil || unpackDNSMessage(wire).Rcode != dns.RcodeRefused {
				t.Fatalf("lost replacement response: %v", err)
			}
			q := dnsTestRequest(t, "after.example.", 17)
			if err := netutils.WriteDNSFrame(client, dnsTestWire(t, q)); err != nil {
				t.Fatal(err)
			}
			wire, err = netutils.ReadDNSFrame(client)
			if err != nil || !dnsResponseMatches(q.MessageCopy(), unpackDNSMessage(wire)) {
				t.Fatalf("dedicated EOF closed unrelated query: %v", err)
			}
		})
	}
}

func TestDNSTCPHalfCloseDrainsTransfer(t *testing.T) {
	client, accepted := relayTestTCPPair(t)
	writeLast := make(chan struct{})
	serveTestDNSTCP(t, client, accepted, nil, func(peer net.Conn) {
		wire, err := netutils.ReadDNSFrame(peer)
		if err != nil {
			return
		}
		q := unpackDNSMessage(wire)
		r := new(dns.Msg).SetReply(q)
		r.Answer = []dns.RR{dnsTransferTestSOA(q.Question[0].Name, 2)}
		if err := netutils.WriteDNSFrame(peer, dnsTestWire(t, plugin.DNSMessage(r))); err != nil {
			return
		}
		select {
		case <-writeLast:
		case <-t.Context().Done():
			return
		}
		r.Question = nil
		if err := netutils.WriteDNSFrame(peer, dnsTestWire(t, plugin.DNSMessage(r))); err != nil {
			return
		}
		// A successful transfer need not end the upstream TCP connection.
		_, _ = peer.Read(make([]byte, 1))
	})
	q := new(dns.Msg).SetQuestion("zone.example.", dns.TypeAXFR)
	if err := netutils.WriteDNSFrame(client, dnsTestWire(t, plugin.DNSMessage(q))); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := netutils.ReadDNSFrame(client); err != nil {
		t.Fatalf("read first response: %v", err)
	}
	close(writeLast)
	wire, err := netutils.ReadDNSFrame(client)
	last := unpackDNSMessage(wire)
	if err != nil || last == nil || last.Id != q.Id || len(last.Answer) != 1 {
		t.Fatalf("read final response after half-close: %v", err)
	}
	if _, err := netutils.ReadDNSFrame(client); !errors.Is(err, io.EOF) {
		t.Fatalf("completed transfer still held the client open: %v", err)
	}
}

func dnsTransferTestSOA(name string, serial uint32) *dns.SOA {
	return &dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns.example.", Mbox: "admin.example.", Serial: serial}
}

func TestDNSZoneTransferBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		client  uint32
		qtype   uint16
		answers [][]uint32
	}{
		{"full", 0, dns.TypeAXFR, [][]uint32{{3, 3}}},
		{"unchanged", 3, dns.TypeIXFR, [][]uint32{{3}}},
		{"fallback", 1, dns.TypeIXFR, [][]uint32{{3}, {3}}},
		{"incremental", 1, dns.TypeIXFR, [][]uint32{{3}, {1, 2}, {2, 3}, {3}}},
		{"serial-wrap", ^uint32(0), dns.TypeIXFR, [][]uint32{{0}, {^uint32(0), 0}, {0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const zone = "zone.example."
			q := new(dns.Msg).SetQuestion(zone, tc.qtype)
			if tc.qtype == dns.TypeIXFR {
				q.Ns = []dns.RR{dnsTransferTestSOA(zone, tc.client)}
			}
			var boundary dnsTransferBoundary
			for i, serials := range tc.answers {
				r := new(dns.Msg).SetReply(q)
				if i != 0 {
					r.Question = nil
				}
				for _, serial := range serials {
					r.Answer = append(r.Answer, dnsTransferTestSOA(zone, serial))
				}
				if got, want := boundary.finished(q, r), i == len(tc.answers)-1; got != want {
					t.Fatalf("frame %d: finished = %t, want %t", i+1, got, want)
				}
			}
		})
	}
}

func TestDNSIndependentExchangeCannotStartTransfer(t *testing.T) {
	outcome := make(chan error, 1)
	probe := dnsTestMiddleware(func(next plugin.DNSHandler) plugin.DNSHandler {
		return func(ctx context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			_, err := next(ctx, r.Fork())
			outcome <- err
			return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetReply(r.MessageCopy()))}, nil
		}
	})
	host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "probe", Plugin: probe})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	client := dnsTCPTestClient(t, host, func(net.Conn) { t.Error("auxiliary transfer dialed upstream") })
	m := new(dns.Msg).SetQuestion("zone.example.", dns.TypeAXFR)
	if err := netutils.WriteDNSFrame(client, dnsTestWire(t, plugin.DNSMessage(m))); err != nil {
		t.Fatal(err)
	}
	if _, err := netutils.ReadDNSFrame(client); err != nil {
		t.Fatal(err)
	}
	if err := <-outcome; err == nil {
		t.Fatal("auxiliary transfer was accepted")
	}
}

type dnsCallbackPlugin struct{ handle plugin.DNSHandler }

func (*dnsCallbackPlugin) Plan() plugin.Plan                             { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }
func (p *dnsCallbackPlugin) WrapDNS(plugin.DNSHandler) plugin.DNSHandler { return p.handle }

func TestDNSUDPDeviceRouteAdmissionAndCancellation(t *testing.T) {
	for _, stale := range []bool{true, false} {
		t.Run(map[bool]string{true: "stale", false: "changed during local response"}[stale], func(t *testing.T) {
			entered := make(chan struct{}, 1)
			p := &dnsCallbackPlugin{handle: func(ctx context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				entered <- struct{}{}
				<-ctx.Done()
				return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetReply(r.MessageCopy()))}, nil
			}}
			host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "local", Plugin: p})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			mac := [6]byte{1, 2, 3, 4, 5, 6}
			routes := &deviceRoutes{devices: map[[6]byte]*deviceRoute{mac: {epoch: 2}}}
			identity := routingResult{Mac: mac, RouteEpoch: 2, CaptureFlags: captureDNS}
			lease, err := routes.acquire(&identity)
			if err != nil {
				t.Fatal(err)
			}
			if stale {
				identity.RouteEpoch--
			}
			c := &ControlPlane{dnsRelay: newDNSRelay(), mitmHost: host, deviceRoutes: routes}
			defer c.dnsRelay.Close()
			c.handleDNSUDP(dnsTestWire(t, dnsTestRequest(t, "local.example.", 1)), netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53"), identity)
			if !stale {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("local plugin not admitted")
				}
				lease.Abort(errRouteChanged)
			}
			done := make(chan struct{})
			go func() { c.dnsRelay.active.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("route cancellation did not finish local response")
			}
			if len(entered) != 0 {
				t.Fatal("stale packet reached local-answer plugin")
			}
		})
	}
}
