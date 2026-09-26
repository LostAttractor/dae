// SPDX-License-Identifier: AGPL-3.0-only

//go:build dns_plugins_integration

package dnsrouter_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cache "github.com/daeuniverse/dae-plugin-dns-cache"
	router "github.com/daeuniverse/dae-plugin-dns-router"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dns "github.com/miekg/dns"
)

func TestDNSPluginComposition(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.sgmodule"), []byte("[Host]\nlocal.example = 198.51.100.1\nalias.example = local.example\nassigned.example = server:192.0.2.54:5353\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sections, err := config_parser.Parse(`cache {} surge { module { 'file:hosts.sgmodule' } } router { upstream { test:'tcp+udp://192.0.2.53' } routing { request { fallback:test } } }`)
	if err != nil {
		t.Fatal(err)
	}
	specs := []plugin.Spec{{ID: "cache", Type: "cache", Config: sections[0]}, {ID: "surge", Type: "surge", Config: sections[1]}, {ID: "router", Type: "router", Config: sections[2]}}
	configured, err := mitm.Configure(map[string]plugin.Definition{"cache": cache.Plugin, "surge": surge.Plugin, "router": router.Plugin}, specs)
	if err != nil {
		t.Fatal(err)
	}
	h, err := configured.Load(t.Context(), mitm.Options{DisableHTTP: true}, plugin.Services{BaseDir: dir, PrepareClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var mu sync.Mutex
	var calls []string
	dial := func(ctx context.Context, network, target, hostname string) (net.Conn, error) {
		mu.Lock()
		calls = append(calls, network+" "+target)
		mu.Unlock()
		conn, peer := net.Pipe()
		go func() {
			defer peer.Close()
			d := &dns.Conn{Conn: peer}
			var m *dns.Msg
			var err error
			if network == "tcp" {
				m, err = d.ReadMsg()
			} else {
				buffer := make([]byte, 65535)
				var n int
				n, err = peer.Read(buffer)
				m = new(dns.Msg)
				if err == nil {
					err = m.Unpack(buffer[:n])
				}
			}
			if err != nil {
				return
			}
			m.Response = true
			if network == "udp" {
				m.Truncated = true
			} else {
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.2")}}
			}
			if network == "tcp" {
				_ = d.WriteMsg(m)
			} else {
				wire, _ := m.Pack()
				_, _ = peer.Write(wire)
			}
		}()
		return conn, nil
	}
	terminalCalls := 0
	terminal := func(_ context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		terminalCalls++
		if !r.ServerAssigned || r.Destination.String() != "192.0.2.54:5353" {
			return nil, fmt.Errorf("lost assignment: %+v", r)
		}
		m := new(dns.Msg).SetReply(r.MessageCopy())
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.3")}}
		return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(m)}, nil
	}
	for _, name := range []string{"local.example.", "alias.example.", "assigned.example.", "router.example."} {
		t.Run(name, func(t *testing.T) {
			m := new(dns.Msg).SetQuestion(name, dns.TypeA)
			request := &plugin.DNSExchange{DNSPacket: plugin.DNSMessage(m), Network: "udp", Source: netip.MustParseAddrPort("192.0.2.1:1000"), OriginalDestination: netip.MustParseAddrPort("192.0.2.1:53"), Destination: netip.MustParseAddrPort("192.0.2.1:53"), ContextKey: "source/profile", DialContext: dial}
			var first time.Time
			for attempt := range 2 {
				m.Id++
				request.DNSPacket = plugin.DNSMessage(m)
				response, err := h.HandleDNS(t.Context(), request, terminal, func(response *plugin.DNSResponse) error {
					wire, err := response.Wire()
					if err != nil {
						return err
					}
					response.DNSPacket = plugin.DNSWire(wire)
					if response.ReceivedAt.IsZero() {
						response.ReceivedAt = time.Now()
					}
					h.ObserveDNS(t.Context(), request, response)
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if response.Cached != (attempt == 1) || response.MessageCopy().Id != request.MessageCopy().Id || len(response.MessageCopy().Answer) == 0 {
					t.Fatalf("bad response: %+v", response)
				}
				if attempt == 0 {
					first = response.ReceivedAt
				} else if !first.Equal(response.ReceivedAt) {
					t.Fatal("cache renewed receipt time")
				}
			}
		})
	}
	if terminalCalls != 1 {
		t.Fatalf("assignment/cache terminal calls=%d", terminalCalls)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(calls) != "[udp 192.0.2.53:53 tcp 192.0.2.53:53]" {
		t.Fatalf("fallback/cache dials=%v", calls)
	}
}

func TestMultiServerCancellationJoinsLoser(t *testing.T) {
	r := new(router.Router)
	started, stopped := make(chan struct{}), make(chan struct{})
	m := new(dns.Msg).SetQuestion("race.example.", dns.TypeA)
	request := &plugin.DNSExchange{DNSPacket: plugin.DNSMessage(m)}
	request.DialContext = func(ctx context.Context, network, target, hostname string) (net.Conn, error) {
		if target == "192.0.2.54:53" {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil, ctx.Err()
		}
		<-started
		conn, peer := net.Pipe()
		go func() {
			defer peer.Close()
			b := make([]byte, 1024)
			n, err := peer.Read(b)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(b[:n]) != nil {
				return
			}
			q.Response = true
			wire, _ := q.Pack()
			_, _ = peer.Write(wire)
		}()
		return conn, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response, err := r.ResolveDNS(ctx, request, []string{"192.0.2.53", "192.0.2.54"})
	if err != nil || response == nil {
		t.Fatalf("winner: %+v %v", response, err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("resolver returned before loser stopped")
	}
}
