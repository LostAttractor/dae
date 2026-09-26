// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func TestSurgeAliasValidatesDownstreamBeforeRewriting(t *testing.T) {
	e := moduleScopeEngine(t, moduleScopeModule(t, "dns", "", "[Host]\nalias.example=target.example", nil))
	for _, test := range []struct {
		name   string
		mutate func(*dns.Msg)
	}{
		{"ID", func(m *dns.Msg) { m.Id++ }},
		{"name", func(m *dns.Msg) { m.Question[0].Name = "unrelated.example." }},
		{"type", func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }},
		{"class", func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }},
		{"opcode", func(m *dns.Msg) { m.Opcode = dns.OpcodeNotify }},
		{"QR", func(m *dns.Msg) { m.Response = false }},
		{"empty success", func(m *dns.Msg) { m.Question = nil }},
		{"trailing bytes", func(*dns.Msg) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			q := hostDNSRequest(t, "alias.example.", dns.TypeA)
			response, err := e.WrapDNS(func(_ context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				message := new(dns.Msg).SetReply(r.MessageCopy())
				rr, _ := dns.NewRR("target.example. 60 IN A 192.0.2.66")
				message.Answer = []dns.RR{rr}
				test.mutate(message)
				wire, _ := message.Pack()
				if test.name == "trailing bytes" {
					wire = append(wire, 0xff)
				}
				return &plugin.DNSResponse{DNSPacket: plugin.DNSWire(wire)}, nil
			})(t.Context(), q)
			if err == nil || response != nil {
				t.Fatalf("invalid response was repaired: %+v %v", response, err)
			}
		})
	}
	q := hostDNSRequest(t, "alias.example.", dns.TypeA)
	response, err := e.WrapDNS(func(_ context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		message := new(dns.Msg).SetReply(r.MessageCopy())
		message.Question, message.Rcode = nil, dns.RcodeRefused
		wire, _ := message.Pack()
		return &plugin.DNSResponse{DNSPacket: plugin.DNSWire(wire)}, nil
	})(t.Context(), q)
	if err != nil || response.MessageCopy().Rcode != dns.RcodeRefused || response.MessageCopy().Question[0] != q.MessageCopy().Question[0] {
		t.Fatalf("valid alias error response lost: %+v %v", response, err)
	}
}

func TestSurgeDNSBinaryHTTP(t *testing.T) {
	body := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		body <- data
		if r.Header.Get("X-Value") != "1, 2" {
			t.Error("DNS HTTP header normalization lost")
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	runtime := testRuntime(t, RuntimeOptions{})
	result, err := runtime.Run(t.Context(), fmt.Sprintf(`
$httpClient.post({url:%q,headers:{"X-Value":[1,2]},body:new Uint8Array([0,255]),"binary-mode":true},(error,response,data)=>{
  if(error)throw Error(error);
  if(!(data instanceof Uint8Array)||data[0]!==0||data[1]!==255)throw Error("binary response");
  $done({address:"192.0.2.1"});
});`, server.URL), Invocation{ScriptType: "dns", Domain: "binary.example", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if result.DNS.Address != "192.0.2.1" || !bytes.Equal(<-body, []byte{0, 255}) {
		t.Fatal("binary HTTP or DNS result changed")
	}
}

func TestSurgeDNSScriptBudgetIncludesQueue(t *testing.T) {
	for _, explicit := range []bool{true, false} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			m := moduleScopeModule(t, "dns", "", "[Host]\nscript.example=script:answer\n[Script]\nanswer=type=dns,script-path=answer.js", map[string]string{"answer": `$done({address:"192.0.2.1"})`})
			e := moduleScopeEngine(t, m)
			if explicit {
				m.Scripts[0].Timeout = 30 * time.Millisecond
			} else {
				e.options.ScriptTimeout = 30 * time.Millisecond
			}
			e.slots = make(chan struct{}, 1)
			e.slots <- struct{}{}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			start := time.Now()
			_, err := e.WrapDNS(nil)(ctx, hostDNSRequest(t, "script.example.", dns.TypeA))
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("script budget omitted queue: %s %v", time.Since(start), err)
			}
		})
	}
}

func TestSurgeHostPolicyFollowsFirstMatchingInstance(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		firstModule := moduleScopeModule(t, "first", "", "[Host]\nexample.com=192.0.2.1", nil)
		firstModule.UseHostsForProxy = enabled
		secondModule := moduleScopeModule(t, "second", "", "[Host]\nexample.com=192.0.2.2\nother.example=192.0.2.3", nil)
		secondModule.UseHostsForProxy = !enabled
		first, second := moduleScopeEngine(t, firstModule), moduleScopeEngine(t, secondModule)
		host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "first", Plugin: first}, mitm.Instance{ID: "second", Plugin: second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = host.Close() })
		q := hostDNSRequest(t, "example.com.", dns.TypeA)
		response, err := host.HandleDNS(t.Context(), q, nil, func(*plugin.DNSResponse) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if response.MessageCopy().Answer[0].(*dns.A).A.String() != "192.0.2.1" || host.UseDNSAddress("example.com", true) != enabled {
			t.Fatal("shadowed Host changed the winning entry's proxy policy")
		}
		if host.UseDNSAddress("other.example", true) != !enabled || host.UseDNSAddress("absent.example", true) {
			t.Fatal("nonmatching instance stopped policy lookup")
		}
	}
}

// Each test owns the global resolver until cleanup; these tests must not run in
// parallel. Both Go address lookups and raw negative queries use the Dial hook.
func hostSystemResolver(t *testing.T, handler dns.Handler) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, tcp.Addr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old })
}

func TestSurgeSystemDNSNegativeReplies(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
			t.Run(network+dns.RcodeToString[rcode], func(t *testing.T) {
				hostSystemResolver(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
					response := new(dns.Msg).SetReply(q)
					response.Rcode, response.RecursionAvailable = rcode, true
					soa, _ := dns.NewRR("example. 60 IN SOA ns.example. hostmaster.example. 1 60 60 60 60")
					response.Ns = []dns.RR{soa}
					_ = w.WriteMsg(response)
				}))
				q := hostDNSRequest(t, "ipv4-only.example.", dns.TypeAAAA)
				q.Network = network
				response, err := resolveHostServers(t.Context(), q, []string{"system"}, nil)
				if err != nil {
					t.Fatal(err)
				}
				message := response.MessageCopy()
				if message.Rcode != rcode || len(message.Answer) != 0 || len(message.Ns) != 1 || message.Id != q.MessageCopy().Id {
					t.Fatalf("negative semantics lost: %s", message)
				}
			})
		}
	}
}

func TestSurgeSystemDNSAbsoluteName(t *testing.T) {
	var mu sync.Mutex
	var questions []string
	hostSystemResolver(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		mu.Lock()
		questions = append(questions, q.Question[0].Name)
		mu.Unlock()
		response := new(dns.Msg).SetReply(q)
		response.RecursionAvailable = true
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.66")
		response.Answer = []dns.RR{rr}
		_ = w.WriteMsg(response)
	}))
	response, err := resolveHostServers(t.Context(), hostDNSRequest(t, "www.example.com.", dns.TypeA), []string{"system"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(questions) != 1 || questions[0] != "www.example.com." || response.MessageCopy().Answer[0].Header().Name != "www.example.com." {
		t.Fatalf("absolute name used search domains: questions=%v response=%s", questions, response.MessageCopy())
	}
}
