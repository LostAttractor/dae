// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	policy "github.com/daeuniverse/dae/plugins/dns-router/policy"
	dns "github.com/miekg/dns"
)

type exchangeDialer func(context.Context, string, string) (net.Conn, error)

func (d exchangeDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return d(ctx, network, target)
}
func (exchangeDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet dial")
}

func TestExchangeAdmission(t *testing.T) {
	for _, scheme := range []policy.UpstreamScheme{"udp", "tcp", "tls", "https", "quic", "h3"} {
		upstream := &policy.Upstream{Scheme: scheme}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		query := testQuery("example.com.", dns.TypeA, 42)
		if _, err := Exchange(ctx, upstream, nil, netip.AddrPort{}, "", query); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s pre-canceled exchange: %v", scheme, err)
		}
		for _, signature := range []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Rrtype: dns.TypeTSIG}}, &dns.SIG{Hdr: dns.RR_Header{Rrtype: dns.TypeSIG}}} {
			query.Extra = []dns.RR{signature}
			if _, err := Exchange(t.Context(), upstream, nil, netip.AddrPort{}, "", query); err == nil {
				t.Fatalf("%s accepted signed query", scheme)
			}
		}
		if scheme != "https" && scheme != "h3" {
			for _, qtype := range []uint16{dns.TypeAXFR, dns.TypeIXFR} {
				if _, err := Exchange(t.Context(), upstream, nil, netip.AddrPort{}, "", testQuery("example.com.", qtype, 42)); err == nil {
					t.Fatalf("%s admitted unsupported transfer", scheme)
				}
			}
		}
	}
}

func TestTCPExchangeDiscardsInvalidFrames(t *testing.T) {
	for _, kind := range []string{"ID", "QR", "opcode", "name", "class", "type", "trailing", "short section"} {
		t.Run(kind, func(t *testing.T) {
			dial := exchangeDialer(func(context.Context, string, string) (net.Conn, error) {
				c, p := net.Pipe()
				go func() {
					defer p.Close()
					dc := &dns.Conn{Conn: p}
					query, err := dc.ReadMsg()
					if err != nil {
						return
					}
					bad := new(dns.Msg).SetReply(query)
					switch kind {
					case "ID":
						bad.Id++
					case "QR":
						bad.Response = false
					case "opcode":
						bad.Opcode = dns.OpcodeNotify
					case "name":
						bad.Question[0].Name = "wrong.example."
					case "class":
						bad.Question[0].Qclass = dns.ClassCHAOS
					case "type":
						bad.Question[0].Qtype = dns.TypeAAAA
					}
					wire, _ := bad.Pack()
					if kind == "trailing" {
						wire = append(wire, 0)
					}
					if kind == "short section" {
						binary.BigEndian.PutUint16(wire[6:8], 1)
					}
					frame := make([]byte, 2+len(wire))
					binary.BigEndian.PutUint16(frame, uint16(len(wire)))
					copy(frame[2:], wire)
					_, _ = p.Write(frame)
					good := new(dns.Msg).SetReply(query)
					good.Question[0].Name = strings.ToUpper(good.Question[0].Name)
					good.Answer = []dns.RR{testARecord(query.Question[0].Name, "192.0.2.1")}
					_ = dc.WriteMsg(good)
				}()
				return c, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			query := testQuery("example.com.", dns.TypeA, 42)
			response, err := Exchange(ctx, &policy.Upstream{Scheme: "tcp"}, dial, netip.MustParseAddrPort("192.0.2.53:53"), "tcp", query)
			if err != nil || len(response.Answer) != 1 || response.Id != 42 || query.Response {
				t.Fatalf("invalid frame affected exchange: %v %v", response, err)
			}
		})
	}
}

func TestUDPExchangesUseDistinctSockets(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ports := make(chan int, 2)
	go func() {
		type received struct {
			query   dns.Msg
			address *net.UDPAddr
		}
		var requests []received
		for range 2 {
			wire := make([]byte, 65535)
			n, addr, err := server.ReadFromUDP(wire)
			if err != nil {
				return
			}
			query := new(dns.Msg)
			if query.Unpack(wire[:n]) != nil {
				return
			}
			ports <- addr.Port
			requests = append(requests, received{*query, addr})
		}
		for _, r := range requests {
			wire, _ := new(dns.Msg).SetReply(&r.query).Pack()
			_, _ = server.WriteToUDP(wire, r.address)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			response, err := Exchange(ctx, &policy.Upstream{Scheme: "udp"}, exchangeDialer((&net.Dialer{}).DialContext), server.LocalAddr().(*net.UDPAddr).AddrPort(), "udp", testQuery("example.com.", dns.TypeA, 42))
			if err != nil || response.Id != 42 {
				t.Errorf("UDP response: %v %v", response, err)
			}
		})
	}
	workers.Wait()
	if len(ports) != 2 {
		t.Fatal("queries did not reach server")
	}
	if <-ports == <-ports {
		t.Fatal("concurrent queries reused a UDP source port")
	}
}

func TestTCPUpdateDoesNotReplayPartialWrite(t *testing.T) {
	calls := 0
	dial := exchangeDialer(func(context.Context, string, string) (net.Conn, error) {
		calls++
		c, p := net.Pipe()
		go func() { defer p.Close(); _, _ = io.ReadFull(p, make([]byte, 3)) }()
		return c, nil
	})
	query := testQuery("example.com.", dns.TypeSOA, 42)
	query.Opcode = dns.OpcodeUpdate
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response, err := Exchange(ctx, &policy.Upstream{Scheme: "tcp"}, dial, netip.MustParseAddrPort("192.0.2.53:53"), "tcp", query)
	if err == nil || response != nil || calls != 1 || query.Response {
		t.Fatalf("partial update replayed: %d %v %v", calls, response, err)
	}
}
