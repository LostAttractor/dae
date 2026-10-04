// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

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
			stream := newDNSStream(conn, func([]byte) error { t.Error("correlated error treated as unsolicited"); return nil }, func() {})
			defer stream.close()
			q := dnsTestRequest(t, "error.example.", 123)
			go func() {
				for range 2 {
					wire, err := readDNSFrame(peer)
					if err != nil {
						return
					}
					request := unpackDNSMessage(wire)
					response := new(dns.Msg).SetReply(request)
					if request.Id == q.MessageCopy().Id {
						response.Question, response.Rcode = nil, rcode
					}
					wire, _ = response.Pack()
					if writeDNSFrame(peer, wire) != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			response, err := stream.exchange(ctx, q)
			if err != nil || response.MessageCopy().Rcode != rcode || len(response.MessageCopy().Question) != 0 {
				t.Fatalf("header-only response was lost/rewritten: %+v %v", response, err)
			}
			if dnsResponseMatches(q.MessageCopy(), response.MessageCopy()) {
				t.Fatal("header-only error became evidence")
			}
			if _, err := stream.exchange(ctx, dnsTestRequest(t, "next.example.", 124)); err != nil {
				t.Fatalf("error response poisoned shared connection: %v", err)
			}
		})
	}
}

func TestDNSStreamHeaderOnlyErrorWithRepeatedID(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	unsolicited := make(chan struct{}, 1)
	stream := newDNSStream(conn, func([]byte) error { unsolicited <- struct{}{}; return nil }, func() {})
	defer stream.close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	finished := make(chan error, 2)
	for _, name := range []string{"one.example.", "two.example."} {
		go func() { _, err := stream.exchange(ctx, dnsTestRequest(t, name, 7)); finished <- err }()
	}
	requests := make([]*dns.Msg, 2)
	for i := range requests {
		wire, err := readDNSFrame(peer)
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = unpackDNSMessage(wire)
	}
	bad := new(dns.Msg).SetReply(requests[0])
	bad.Question, bad.Rcode = nil, dns.RcodeFormatError
	wire, _ := bad.Pack()
	if err := writeDNSFrame(peer, wire); err != nil {
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
		if err := writeDNSFrame(peer, wire); err != nil {
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

func dnsTCPTestClient(t *testing.T, server func(net.Conn)) net.Conn {
	t.Helper()
	group := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		conn, peer := net.Pipe()
		go func() { defer peer.Close(); server(peer) }()
		return conn, nil
	})
	c := &ControlPlane{dnsRelay: newDNSRelay(), outbounds: []*outbound.DialerGroup{group}}
	client, accepted := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer accepted.Close()
		_ = c.serveDNSTCP(shortDNSIdleConn{accepted}, netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: 8})
	}()
	t.Cleanup(func() { client.Close(); c.dnsRelay.Close(); <-done })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client
}

func TestDNSTCPUpstreamEOFDrainsLastResponse(t *testing.T) {
	client := dnsTCPTestClient(t, func(peer net.Conn) {
		wire, err := readDNSFrame(peer)
		if err != nil {
			return
		}
		message := unpackDNSMessage(wire)
		message.Response = true
		wire, _ = message.Pack()
		_ = writeDNSFrame(peer, wire)
	})
	query := dnsTestRequest(t, "eof.example.", 1)
	if err := writeDNSFrame(client, dnsTestWire(t, query)); err != nil {
		t.Fatal(err)
	}
	// Give the upstream time to close while delivery is blocked on this client.
	time.Sleep(20 * time.Millisecond)
	wire, err := readDNSFrame(client)
	if err != nil || !dnsResponseMatches(query.MessageCopy(), unpackDNSMessage(wire)) {
		t.Fatalf("lost last response: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := readDNSFrame(client); !errors.Is(err, io.EOF) {
		t.Fatalf("upstream EOF not propagated: %v", err)
	}
}

func TestDNSTCPActiveTransferAndIdleExpiry(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeAXFR, dns.TypeIXFR} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			const frames = 60
			client := dnsTCPTestClient(t, func(peer net.Conn) {
				wire, err := readDNSFrame(peer)
				if err != nil {
					return
				}
				message := unpackDNSMessage(wire)
				message.Response = true
				for range frames {
					wire, _ = message.Pack()
					if writeDNSFrame(peer, wire) != nil {
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
			if err := writeDNSFrame(client, dnsTestWire(t, query)); err != nil {
				t.Fatal(err)
			}
			for i := range frames {
				if _, err := readDNSFrame(client); err != nil {
					t.Fatalf("active transfer stopped at frame %d: %v", i, err)
				}
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := readDNSFrame(client); !errors.Is(err, io.EOF) {
				t.Fatalf("idle connection not collected: %v", err)
			}
		})
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
			identity := routingResult{Mac: mac, RouteEpoch: 2, CaptureFlags: 8}
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
