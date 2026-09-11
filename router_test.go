// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dns "github.com/miekg/dns"
)

func testRouter(t *testing.T, body string) *Router {
	t.Helper()
	sections, err := config_parser.Parse("router {" + body + "}")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Setup(t.Context(), plugin.Spec{Config: sections[0]}, plugin.Services{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := p.(*Router)
	t.Cleanup(func() { r.Close() })
	return r
}

func TestAsisPreservesDownstreamError(t *testing.T) {
	r := testRouter(t, "")
	m := new(dns.Msg).SetQuestion("failed.example.", dns.TypeA)
	wire, _ := new(dns.Msg).SetReply(m).Pack()
	want := errors.New("downstream exchange failed")
	_, err := r.WrapDNS(func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) {
		return &plugin.DNSResponse{Wire: wire}, want
	})(t.Context(), &plugin.DNSRequest{Message: m, Source: netip.MustParseAddrPort("192.0.2.1:1234"), OriginalDestination: netip.MustParseAddrPort("192.0.2.53:53")})
	if !errors.Is(err, want) {
		t.Fatalf("downstream error lost: %v", err)
	}
}

func TestRouterRequestResponsePolicyAndPreference(t *testing.T) {
	for _, prefer := range []string{"", "ipversion_prefer:4"} {
		t.Run(prefer, func(t *testing.T) {
			r := testRouter(t, prefer+`
upstream { first:'udp://192.0.2.53:53' second:'udp://192.0.2.54:53' }
routing { request { qname(full:blocked.example) -> reject fallback:first }
response { upstream(first) -> second fallback:accept } }
`)
			m := new(dns.Msg).SetQuestion("test.example.", dns.TypeAAAA)
			wire, _ := m.Pack()
			request := &plugin.DNSRequest{Message: m, Wire: wire, Network: "udp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), OriginalDestination: netip.MustParseAddrPort("192.0.2.53:53")}
			var mu sync.Mutex
			var calls []string
			request.DialContext = func(_ context.Context, network, target, hostname string) (net.Conn, error) {
				mu.Lock()
				calls = append(calls, network+" "+target)
				mu.Unlock()
				conn, peer := net.Pipe()
				go func() {
					defer peer.Close()
					data := make([]byte, 65535)
					n, err := peer.Read(data)
					if err != nil {
						return
					}
					q := new(dns.Msg)
					if q.Unpack(data[:n]) != nil {
						return
					}
					q.Response = true
					if q.Question[0].Qtype == dns.TypeA {
						q.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.1")}}
					} else {
						q.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
					}
					wire, _ := q.Pack()
					_, _ = peer.Write(wire)
				}()
				return conn, nil
			}
			response, err := r.WrapDNS(func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) {
				t.Fatal("unexpected asis")
				return nil, nil
			})(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if (len(response.Message.Answer) == 0) != (prefer != "") {
				t.Fatalf("family preference: %s", response.Message)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(calls) < 2 || !strings.Contains(strings.Join(calls, ","), "192.0.2.54:53") {
				t.Fatalf("response reroute missing: %v", calls)
			}
			blocked := request.Copy()
			blocked.Message.Question[0].Name = "blocked.example."
			blocked.Wire, _ = blocked.Message.Pack()
			blocked.Message.Question[0].Qtype = dns.TypeA
			response, err = r.WrapDNS(nil)(t.Context(), blocked)
			if err != nil || len(response.Message.Answer) != 0 {
				t.Fatalf("request rejection: %+v %v", response, err)
			}
		})
	}
}

func TestExplicitServerAndAsisPreserveWire(t *testing.T) {
	r := testRouter(t, "routing { request { fallback:reject } }")
	m := new(dns.Msg).SetQuestion("explicit.example.", dns.TypeA)
	request := &plugin.DNSRequest{Message: m, ServerAssigned: true}
	called := false
	_, err := r.WrapDNS(func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) { called = true; return nil, nil })(t.Context(), request)
	if err != nil || !called {
		t.Fatal("general policy overrode explicit server")
	}
}
