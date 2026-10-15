// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
	policy "github.com/daeuniverse/dae/plugins/dns-router/policy"
	dns "github.com/miekg/dns"
)

func safetyRequest(qtype uint16) *plugin.DNSExchange {
	m := new(dns.Msg).SetQuestion("test.example.", qtype)
	wire, _ := m.Pack()
	return &plugin.DNSExchange{DNSPacket: plugin.DNSWire(wire), Network: "udp", Source: netip.MustParseAddrPort("192.0.2.1:2345"), OriginalDestination: netip.MustParseAddrPort("192.0.2.53:53")}
}

func packetWire(t *testing.T, packet interface{ Wire() ([]byte, error) }) []byte {
	t.Helper()
	wire, err := packet.Wire()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestTCPFallbackReservesCallerBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	q := safetyRequest(dns.TypeA)
	var tcp atomic.Bool
	q.DialContext = func(_ context.Context, network, target, hostname string) (net.Conn, error) {
		c, p := net.Pipe()
		go func() {
			defer p.Close()
			if network == "udp" {
				buf := make([]byte, 4096)
				_, _ = p.Read(buf)
				_, _ = p.Read(buf)
				return
			}
			tcp.Store(true)
			d := &dns.Conn{Conn: p}
			m, err := d.ReadMsg()
			if err == nil {
				_ = d.WriteMsg(new(dns.Msg).SetReply(m))
			}
		}()
		return c, nil
	}
	raw, _ := url.Parse("tcp+udp://192.0.2.53:53")
	upstream, err := policy.NewUpstream(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Exchange(ctx, q, upstream)
	if err != nil || !tcp.Load() {
		t.Fatalf("TCP fallback not reached: %v %v", tcp.Load(), err)
	}
}

func TestAsisInvalidResponsesBypassPolicy(t *testing.T) {
	r := testRouter(t, `routing { response { fallback:reject } }`)
	for _, kind := range []string{"ID", "question", "trailing bytes", "malformed", "QR", "opcode"} {
		t.Run(kind, func(t *testing.T) {
			q := safetyRequest(dns.TypeA)
			m := new(dns.Msg).SetReply(q.MessageCopy())
			switch kind {
			case "ID":
				m.Id++
			case "question":
				m.Question[0].Name = "other.example."
			case "QR":
				m.Response = false
			case "opcode":
				m.Opcode = dns.OpcodeNotify
			}
			wire, _ := m.Pack()
			if kind == "trailing bytes" {
				wire = append(wire, 0xff)
			}
			if kind == "malformed" {
				wire = []byte{0, 1, 2}
			}
			original := &plugin.DNSResponse{DNSPacket: plugin.DNSWire(wire)}
			got, err := r.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return original, nil })(t.Context(), q)
			if err != nil || got != original || !bytes.Equal(packetWire(t, got), wire) {
				t.Fatalf("invalid frame became a policy answer: %+v %v", got, err)
			}
		})
	}
}

func TestPreferenceIgnoresUncorrelatedProbe(t *testing.T) {
	r := testRouter(t, "ipversion_prefer:4")
	for _, valid := range []bool{false, true} {
		q := safetyRequest(dns.TypeAAAA)
		got, err := r.WrapDNS(func(_ context.Context, req *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			m := new(dns.Msg).SetReply(req.MessageCopy())
			var rr dns.RR
			if req.MessageCopy().Question[0].Qtype == dns.TypeA {
				if !valid {
					m.Id++
				}
				rr, _ = dns.NewRR("test.example. 60 IN A 192.0.2.66")
			} else {
				rr, _ = dns.NewRR("test.example. 60 IN AAAA 2001:db8::66")
			}
			m.Answer = []dns.RR{rr}
			wire, _ := m.Pack()
			return &plugin.DNSResponse{DNSPacket: plugin.DNSWire(wire)}, nil
		})(t.Context(), q)
		if err != nil {
			t.Fatal(err)
		}
		m := responseMessage(q, got)
		if m == nil || (len(m.Answer) == 0) != valid {
			t.Fatalf("incorrect suppression by probe (valid=%v): %v", valid, m)
		}
	}
}

func TestAsisHeaderOnlyErrorsPreserveWire(t *testing.T) {
	for _, body := range []string{"", `routing { response { qname(full:test.example) -> accept fallback:reject } }`} {
		r := testRouter(t, body)
		for _, rcode := range []int{dns.RcodeFormatError, dns.RcodeRefused, dns.RcodeServerFailure} {
			q := safetyRequest(dns.TypeA)
			q.Network = "tcp"
			m := new(dns.Msg).SetReply(q.MessageCopy())
			m.Rcode, m.Question = rcode, nil
			wire, _ := m.Pack()
			for _, packet := range []plugin.DNSPacket{plugin.DNSWire(wire), plugin.DNSMessage(m)} {
				got, err := r.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
					return &plugin.DNSResponse{DNSPacket: packet}, nil
				})(t.Context(), q)
				if err != nil || got == nil || !bytes.Equal(packetWire(t, got), wire) || len(m.Question) != 0 {
					t.Fatalf("header-only %s lost/rewritten: %+v %v", dns.RcodeToString[rcode], got, err)
				}
			}
		}
	}
}

func TestEndpointHostnameReachesBothDialServices(t *testing.T) {
	q := safetyRequest(dns.TypeA)
	called := 0
	q.DialContext = func(_ context.Context, network, target, hostname string) (net.Conn, error) {
		if network != "tcp" || target != "192.0.2.53:443" || hostname != "dns.example" {
			t.Fatal("endpoint identity lost")
		}
		called++
		return nil, nil
	}
	q.ListenPacket = func(_ context.Context, target, hostname string) (net.PacketConn, error) {
		if target != "192.0.2.53:443" || hostname != "dns.example" {
			t.Fatal("packet endpoint identity lost")
		}
		called++
		return nil, nil
	}
	d := requestDialer{q, "dns.example"}
	_, _ = d.DialContext(t.Context(), "tcp", "192.0.2.53:443")
	_, _ = d.ListenPacket(t.Context(), "192.0.2.53:443")
	if called != 2 {
		t.Fatal("dial services not called")
	}
}

func TestPreflightStaticRoutingAndDeferredResources(t *testing.T) {
	for _, test := range []struct {
		body  string
		valid bool
	}{
		{`routing { request { fallback:missing } }`, false},
		{`routing { request { qtype(BAD) -> asis } }`, false},
		{`routing { response { invalid(test) -> accept } }`, false},
		{`routing { request { qname(regex:'[') -> asis } }`, false},
		{`routing { request { dip(mmdb:bad) -> asis } }`, false},
		{`routing { request { qname(ext:missing) -> asis } }`, false},
		{`routing { request { qname(geosite:cn) && qtype(BAD) -> asis } }`, false},
		{`routing { request { qname(geosite:cn) -> missing } }`, false},
		{`upstream { local:'udp://192.0.2.53' } routing { request { qname(ext:'missing.dat:cn') && dip(geoip:cn) && interface(eth0) -> local } response { ip(mmdb:'country.iso_code=CN') -> accept } }`, true},
	} {
		t.Run(test.body, func(t *testing.T) {
			sections, err := config_parser.Parse("router {" + test.body + "}")
			if err != nil {
				t.Fatal(err)
			}
			copy, err := config_parser.Parse("router {" + test.body + "}")
			if err != nil {
				t.Fatal(err)
			}
			spec := plugin.Spec{ID: "router", Type: "router", Config: sections[0]}
			if _, err := Configure(spec); (err == nil) != test.valid {
				t.Fatalf("preflight valid=%v: %v", test.valid, err)
			}
			if !reflect.DeepEqual(sections, copy) {
				t.Fatal("preflight mutated configuration")
			}
			if !test.valid {
				started := false
				definitions := map[string]plugin.Definition{"router": Plugin, "first": {Configure: func(plugin.Spec) (plugin.Factory, error) {
					return func(context.Context, plugin.Services) (plugin.Plugin, error) {
						started = true
						return nil, nil
					}, nil
				}}}
				_, err := pluginhost.Configure(definitions, []plugin.Spec{{ID: "first", Type: "first"}, spec})
				if err == nil || started {
					t.Fatal("invalid router started plugin preparation")
				}
			}
		})
	}
}
