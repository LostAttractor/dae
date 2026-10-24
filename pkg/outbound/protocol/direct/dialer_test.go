// SPDX-License-Identifier: AGPL-3.0-only

package direct

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"

	"github.com/miekg/dns"
)

func TestTCPPrefersIPv6AndHonorsExplicitFamily(t *testing.T) {
	v6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer v6.Close()
	_, port, _ := net.SplitHostPort(v6.Addr().String())
	v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			conn := &dns.Conn{Conn: peer}
			query, err := conn.ReadMsg()
			if err != nil {
				return
			}
			q := query.Question[0]
			header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 0}
			reply := new(dns.Msg).SetReply(query)
			if q.Qtype == dns.TypeA {
				reply.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("127.0.0.1")}}
			} else {
				reply.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("::1")}}
			}
			_ = conn.WriteMsg(reply)
		}()
		return client, nil
	}}
	for _, family := range []int{0, 4, 6} {
		dialer := NewDirectDialer(Option{Resolver: resolver, IPVersion: family})
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("dual-stack.test.", port))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		got4 := conn.RemoteAddr().(*net.TCPAddr).IP.To4() != nil
		_ = conn.Close()
		if got4 != (family == 4) {
			t.Fatalf("explicit family=%d connected over IPv4=%v", family, got4)
		}
		if family == 0 {
			continue
		}
		conn, err = dialer.DialContext(t.Context(), "udp", net.JoinHostPort("dual-stack.test.", port))
		if err != nil {
			t.Fatal(err)
		}
		got4 = conn.RemoteAddr().(*net.UDPAddr).IP.To4() != nil
		_ = conn.Close()
		if got4 != (family == 4) {
			t.Fatalf("explicit family=%d connected UDP over IPv4=%v", family, got4)
		}
	}
}

func TestUDPDomainUsesLookupInOrder(t *testing.T) {
	if conn, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	} else {
		_ = conn.Close()
	}
	var lookups int
	dialer := NewDirectDialer(Option{IPVersion: 6, Lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		if network != "ip6" || host != "node.test." {
			t.Errorf("lookup(%s, %s)", network, host)
		}
		// A link-local address without a zone cannot be connected.
		return []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("::1")}, nil
	}})
	conn, err := dialer.DialContext(t.Context(), "udp", "node.test.:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if remote := conn.RemoteAddr().String(); remote != "[::1]:53" {
		t.Fatalf("connected to %s", remote)
	}
	addr, err := netproxy.ResolveUDPAddr(t.Context(), dialer, "node.test.:53")
	if err != nil || addr.String() != "[fe80::1]:53" || lookups != 2 {
		t.Fatalf("ResolveUDPAddr = %v, %v after %d lookups", addr, err, lookups)
	}
}
