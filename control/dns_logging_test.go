package control

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestDNSRequestLogging(t *testing.T) {
	logger := log.StandardLogger()
	hooks, level := logger.ReplaceHooks(make(log.LevelHooks)), logger.GetLevel()
	hook := logtest.NewGlobal()
	t.Cleanup(func() {
		logger.ReplaceHooks(hooks)
		logger.SetLevel(level)
	})
	wantErr := errors.New("upstream reset")
	for _, level := range []log.Level{log.InfoLevel, log.DebugLevel} {
		for _, fail := range []bool{false, true} {
			t.Run(level.String()+map[bool]string{false: "/success", true: "/failure"}[fail], func(t *testing.T) {
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
				argument.Outbound = &outbound.DialerGroup{Name: "dns-group"}
				argument.Dialer = &dialer.Dialer{Property: &dialer.Property{Name: "dns-node"}}
				c := fallbackTestController(t, func(*dns.Upstream) (*dialArgument, error) { return argument, nil })
				c.routing = routing
				upstream, err := routing.GetUpstream(context.Background(), 0)
				if err != nil {
					t.Fatal(err)
				}
				cacheFallbackForwarder(c, upstream, argument, &scriptedDNSForwarder{forward: func(_ context.Context, msg *dnsmessage.Msg) error {
					if fail {
						return wantErr
					}
					msg.Response = true
					return nil
				}})
				c.sendPacket = func([]byte, netip.AddrPort, netip.AddrPort) error { return nil }
				source := netip.MustParseAddrPort("192.0.2.10:12345")
				logger.SetLevel(level)
				hook.Reset()
				if err := c.Handle(testDNSQuery("example.com.", dnsmessage.TypeA, 17), &udpRequest{
					src: source, dst: argument.Target, routingResult: &bpfRoutingResult{},
				}); err != nil {
					t.Fatal(err)
				}
				c.activeRequests.Wait()
				entries := hook.AllEntries()
				if level == log.InfoLevel {
					if len(entries) != 0 {
						t.Fatalf("individual DNS query reached info logging: %+v", entries)
					}
					return
				}
				if len(entries) != 1 || entries[0].Level != log.DebugLevel {
					t.Fatalf("query should emit one debug result: %+v", entries)
				}
				entry := entries[0]
				for key, want := range map[string]any{"qname": "example.com.", "qtype": "A"} {
					if entry.Data[key] != want {
						t.Errorf("%s = %v, want %v", key, entry.Data[key], want)
					}
				}
				if fail {
					cause, _ := entry.Data[log.ErrorKey].(error)
					if !errors.Is(cause, wantErr) || entry.Data["source"] != source || !strings.Contains(cause.Error(), upstream.String()) || !strings.Contains(cause.Error(), "dns-group") || !strings.Contains(cause.Error(), "dns-node") {
						t.Fatalf("query failure lost its cause or context: %+v", entry.Data)
					}
				}
			})
		}
	}
}
