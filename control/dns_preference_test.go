package control

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
)

func TestDNSPreferencePreservesUsableAnswer(t *testing.T) {
	for _, preferred := range []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		for _, scenario := range []struct {
			name         string
			queryPrefer  bool
			probeFailure bool
			truncated    bool
			wantAnswers  int
		}{
			{name: "preferred query needs no other family", queryPrefer: true, probeFailure: true, wantAnswers: 1},
			{name: "failed preference probe keeps answer", probeFailure: true, wantAnswers: 1},
			{name: "truncated preference probe keeps answer", truncated: true, wantAnswers: 1},
			{name: "available preference suppresses other family", wantAnswers: 0},
		} {
			t.Run(dnsmessage.TypeToString[preferred]+"/"+scenario.name, func(t *testing.T) {
				conf := &config.Dns{
					Upstream: []config.KeyableString{"test:udp://192.0.2.1:53"},
					Routing: config.DnsRouting{
						Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("test")},
						Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
					},
				}
				routing, err := dns.New(conf, nil, nil, &dns.NewOption{})
				if err != nil {
					t.Fatal(err)
				}
				argument := fallbackTestArgument(consts.L4ProtoStr_UDP, "192.0.2.1:53")
				argument.Direct = true
				argument.Outbound = &outbound.DialerGroup{Name: "direct"}
				argument.Dialer = &dialer.Dialer{Property: &dialer.Property{}}
				c := fallbackTestController(t, func(*dns.Upstream) (*dialArgument, error) { return argument, nil })
				c.routing, c.qtypePrefer = routing, preferred
				qtype := uint16(dnsmessage.TypeA)
				if preferred == dnsmessage.TypeA {
					qtype = dnsmessage.TypeAAAA
				}
				if scenario.queryPrefer {
					qtype = preferred
				}
				var probes atomic.Int32
				upstream, err := routing.GetUpstream(context.Background(), 0)
				if err != nil {
					t.Fatal(err)
				}
				cacheFallbackForwarder(c, upstream, argument, &scriptedDNSForwarder{forward: func(_ context.Context, msg *dnsmessage.Msg) error {
					auxiliary := msg.Question[0].Qtype != qtype
					if auxiliary {
						probes.Add(1)
						if scenario.probeFailure {
							return context.DeadlineExceeded
						}
					}
					response := new(dnsmessage.Msg)
					response.SetReply(msg)
					response.RecursionAvailable = true
					response.Truncated = auxiliary && scenario.truncated
					if msg.Question[0].Qtype == dnsmessage.TypeA {
						response.Answer = []dnsmessage.RR{testARecord("example.com.", "192.0.2.2")}
					} else {
						response.Answer = []dnsmessage.RR{testAAAARecord("example.com.", "2001:db8::2")}
					}
					*msg = *response
					return nil
				}})
				sent := make(chan []byte, 1)
				c.sendPacket = func(data []byte, _, _ netip.AddrPort) error {
					sent <- data
					return nil
				}
				msg := testDNSQuery("example.com.", qtype, 17)
				if err := c.Handle(msg, &udpRequest{src: netip.MustParseAddrPort("192.0.2.10:12345"), dst: argument.Target, routingResult: &bpfRoutingResult{}}); err != nil {
					t.Fatal(err)
				}
				c.activeRequests.Wait()
				select {
				case wire := <-sent:
					var response dnsmessage.Msg
					if err := response.Unpack(wire); err != nil {
						t.Fatal(err)
					}
					if !response.Response || response.Id != 17 || len(response.Answer) != scenario.wantAnswers {
						t.Fatalf("unexpected reply: %v", &response)
					}
				default:
					t.Fatal("successful requested-family response was dropped")
				}
				if scenario.queryPrefer && probes.Load() != 0 {
					t.Fatal("preferred query unnecessarily depends on the other family")
				}
			})
		}
	}
}
