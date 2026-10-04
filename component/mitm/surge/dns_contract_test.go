// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/miekg/dns"
)

func TestDNSScriptCachesTTLWithRoutingIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		module := moduleScopeModule(t, "dns", "", "[Host]\nscript.test=script:answer\n[Script]\nanswer=type=dns,script-path=answer.js", map[string]string{"answer": `
          const count = Number($persistentStore.read("count") || "0") + 1;
          $persistentStore.write(String(count), "count");
          $done({addresses:["192.0.2."+count,"2001:db8::1"],ttl:10});`})
		engine := moduleScopeEngine(t, module)
		handler := engine.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			t.Error("unexpected downstream query")
			return nil, errors.New("downstream")
		})
		query := hostDNSRequest(t, "script.test.", dns.TypeA)
		query.ContextKey = "policy-one"
		first, err := handler(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Second)
		otherID := query.MessageCopy()
		otherID.Id++
		query.DNSPacket = plugin.DNSMessage(otherID)
		cached, err := handler(t.Context(), query)
		if err != nil || !cached.Cached || cached.MessageCopy().Id != otherID.Id || cached.MessageCopy().Answer[0].Header().Ttl != 7 || !cached.ReceivedAt.Equal(first.ReceivedAt) {
			t.Fatalf("cached response: %+v %v", cached, err)
		}
		query.ContextKey = "policy-two"
		isolated, err := handler(t.Context(), query)
		if err != nil || isolated.Cached || isolated.MessageCopy().Answer[0].(*dns.A).A.String() != "192.0.2.2" {
			t.Fatalf("routing cache collision: %+v %v", isolated, err)
		}
		query.ContextKey = "policy-one"
		time.Sleep(7 * time.Second)
		expired, err := handler(t.Context(), query)
		if err != nil || expired.Cached || expired.MessageCopy().Answer[0].(*dns.A).A.String() != "192.0.2.3" {
			t.Fatalf("TTL did not expire: %+v %v", expired, err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := handler(ctx, query); !errors.Is(err, context.Canceled) {
			t.Fatalf("cached reply ignored cancellation: %v", err)
		}
	})
}

func TestDNSScriptMultiplePlainServersWithoutResolver(t *testing.T) {
	request := hostDNSRequest(t, "script.test.", dns.TypeA)
	request.Source = netip.MustParseAddrPort("192.0.2.10:53000")
	request.ContextKey = "source-policy-mark"
	var calls atomic.Int32
	started := make(chan struct{})
	response, err := resolveHostServers(t.Context(), request, []string{"192.0.2.53", "192.0.2.54"}, func(ctx context.Context, query *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		calls.Add(1)
		if !query.Independent() || !query.ServerAssigned || query.Source != request.Source || query.ContextKey != request.ContextKey+"/surge-server/"+query.Destination.String() {
			t.Error("DNS routing identity/lifetime lost")
		}
		if query.Destination.Addr().String() == "192.0.2.53" {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		<-started
		return hostAddressResponse(query, []netip.Addr{netip.MustParseAddr("198.51.100.1")}, 30), nil
	})
	if err != nil || calls.Load() != 2 || response.MessageCopy().Answer[0].(*dns.A).A.String() != "198.51.100.1" {
		t.Fatalf("multi-server result: %+v %v calls=%d", response, err, calls.Load())
	}
	if request.ServerAssigned || request.Destination.String() != "192.0.2.53:53" {
		t.Fatal("caller DNS request modified")
	}
}

func TestDNSPlainServersPreferDefinitiveNegative(t *testing.T) {
	for _, negativeFirst := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			request := hostDNSRequest(t, "missing.test.", dns.TypeA)
			response, err := resolveHostServers(t.Context(), request, []string{"192.0.2.53", "192.0.2.54"}, func(_ context.Context, query *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				negative := query.Destination.Addr().String() == "192.0.2.53"
				if negative != negativeFirst {
					time.Sleep(time.Second)
				}
				message := new(dns.Msg)
				message.SetReply(query.MessageCopy())
				message.Rcode = dns.RcodeServerFailure
				if negative {
					message.Rcode = dns.RcodeNameError
				}
				return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message)}, nil
			})
			if err != nil || response == nil || response.MessageCopy().Rcode != dns.RcodeNameError {
				t.Fatalf("negativeFirst=%t: response=%+v err=%v", negativeFirst, response, err)
			}
		})
	}
}
