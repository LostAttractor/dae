// SPDX-License-Identifier: AGPL-3.0-only

package happyeyeballs

import (
	"context"
	"iter"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testResolver(t *testing.T, delay6, delay4 time.Duration) (*net.Resolver, *atomic.Int32) {
	var queries6 atomic.Int32
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, peer := net.Pipe()
		stop := context.AfterFunc(t.Context(), func() { _ = peer.Close() })
		go func() {
			defer stop()
			defer peer.Close()
			conn := &dns.Conn{Conn: peer}
			query, err := conn.ReadMsg()
			if err != nil {
				return
			}
			q := query.Question[0]
			delay := delay4
			if q.Qtype == dns.TypeAAAA {
				queries6.Add(1)
				delay = delay6
			}
			select {
			case <-time.After(delay):
			case <-t.Context().Done():
				return
			case <-ctx.Done():
				return
			}
			reply := new(dns.Msg).SetReply(query)
			for _, suffix := range []byte{1, 2} {
				header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 0}
				if q.Qtype == dns.TypeA {
					reply.Answer = append(reply.Answer, &dns.A{Hdr: header, A: net.IPv4(192, 0, 2, suffix)})
				} else {
					ip := net.ParseIP("2001:db8::")
					ip[15] = suffix
					reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: header, AAAA: ip})
				}
			}
			_ = conn.WriteMsg(reply)
		}()
		return client, nil
	}}, &queries6
}

func TestResolveDoesNotWaitForSlowFamily(t *testing.T) {
	for _, slow6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "slow A", true: "slow AAAA"}[slow6], func(t *testing.T) {
			delay6, delay4 := time.Duration(0), time.Second
			if slow6 {
				delay6, delay4 = delay4, delay6
			}
			resolver, _ := testResolver(t, delay6, delay4)
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			for ip, err := range Resolve(ctx, resolver, "ip", "dual-stack.test.") {
				if err != nil || ip.Is4() != slow6 {
					t.Fatalf("address=%s error=%v", ip, err)
				}
				return
			}
			t.Fatal("no address")
		})
	}
}

func TestResolveInterleavesAndHonorsExplicitFamily(t *testing.T) {
	resolver, queries6 := testResolver(t, 0, 0)
	var families []bool
	for ip, err := range Resolve(t.Context(), resolver, "ip", "dual-stack.test.") {
		if err != nil {
			t.Fatal(err)
		}
		families = append(families, ip.Is6())
		// Give the independently scheduled A answer time to join the list.
		time.Sleep(10 * time.Millisecond)
	}
	if !slices.Equal(families, []bool{true, false, true, false}) {
		t.Fatal(families)
	}
	before := queries6.Load()
	for ip, err := range Resolve(t.Context(), resolver, "ip4", "dual-stack.test.") {
		if err != nil || !ip.Is4() {
			t.Fatalf("address=%s error=%v", ip, err)
		}
	}
	if queries6.Load() != before {
		t.Fatal("ip4 queried IPv6")
	}
	for _, host := range []string{"192.0.2.1", "fe80::1%eth0"} {
		for ip, err := range Resolve(t.Context(), resolver, "ip", host) {
			if err != nil || ip != netip.MustParseAddr(host) {
				t.Fatalf("literal=%s error=%v", ip, err)
			}
		}
	}
}

func TestLateIPv4AnswerPrecedesRemainingIPv6Addresses(t *testing.T) {
	resolver, _ := testResolver(t, 0, 25*time.Millisecond)
	var v6Attempts atomic.Int32
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ip, err := Race(ctx, func(ctx context.Context) iter.Seq2[netip.Addr, error] {
		return Resolve(ctx, resolver, "ip", "dual-stack.test.")
	}, func(ctx context.Context, ip netip.Addr) (netip.Addr, error) {
		if ip.Is6() {
			v6Attempts.Add(1)
			<-ctx.Done()
			return netip.Addr{}, ctx.Err()
		}
		return ip, nil
	}, nil)
	if err != nil || !ip.Is4() || v6Attempts.Load() != 1 {
		t.Fatalf("winner=%s IPv6 attempts=%d err=%v", ip, v6Attempts.Load(), err)
	}
}
