/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type scriptedDNSForwarder struct {
	forward func(context.Context, *dnsmessage.Msg) error
}

func (f *scriptedDNSForwarder) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	return f.forward(ctx, msg)
}

func (f *scriptedDNSForwarder) Close() error { return nil }

func fallbackTestArgument(proto consts.L4ProtoStr, target string) *dialArgument {
	return &dialArgument{
		networkType: common.NetworkType{L4Proto: proto, IpVersion: consts.IpVersionStr_4},
		Target:      netip.MustParseAddrPort(target),
	}
}

func fallbackTestController(t *testing.T, chooser func(*dns.Upstream) (*dialArgument, error)) *DnsController {
	t.Helper()
	c, err := NewDnsController(nil, &DnsControllerOption{
		BestDialerChooser: func(_ *udpRequest, upstream *dns.Upstream) (*dialArgument, error) {
			return chooser(upstream)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func cacheFallbackForwarder(c *DnsController, upstream *dns.Upstream, argument *dialArgument, forwarder DnsForwarder) {
	c.dnsForwarderCache[makeDNSForwarderKey(upstream, argument)] = forwarder
}

func fallbackTestKey(t *testing.T, msg *dnsmessage.Msg) dnsQueryKey {
	t.Helper()
	key, replaySafe, _ := makeDNSQueryKey(msg, queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA})
	if !replaySafe {
		t.Fatal("test query is not replay-safe")
	}
	return key
}

func TestDNSFallbackRetriesUDPFailureOverTCP(t *testing.T) {
	udpErr := errors.New("UDP unavailable")
	udpArg := fallbackTestArgument(consts.L4ProtoStr_UDP, "192.0.2.1:53")
	tcpArg := fallbackTestArgument(consts.L4ProtoStr_TCP, "192.0.2.2:53")
	chooserCalls := 0
	c := fallbackTestController(t, func(upstream *dns.Upstream) (*dialArgument, error) {
		chooserCalls++
		if upstream.Scheme != dns.UpstreamScheme_TCP {
			t.Fatalf("fallback chooser scheme = %q, want tcp", upstream.Scheme)
		}
		return tcpArg, nil
	})
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP, Hostname: "dns.example", Port: 53}
	cacheFallbackForwarder(c, upstream, udpArg, &scriptedDNSForwarder{forward: func(_ context.Context, msg *dnsmessage.Msg) error {
		msg.Response = true
		msg.Question = nil
		return udpErr
	}})
	cacheFallbackForwarder(c, upstream, tcpArg, &scriptedDNSForwarder{forward: func(_ context.Context, msg *dnsmessage.Msg) error {
		if msg.Response || len(msg.Question) != 1 || msg.Question[0].Name != "example.com." {
			t.Fatalf("TCP fallback received mutated UDP state: %+v", msg)
		}
		response := new(dnsmessage.Msg)
		response.SetReply(msg)
		*msg = *response
		return nil
	}})

	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	pending, used, err := c.dialSendWithFallback(
		context.Background(), msg, &udpRequest{}, upstream, udpArg,
		fallbackTestKey(t, msg), true, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if chooserCalls != 1 || used != tcpArg || !msg.Response {
		t.Fatalf("calls=%d used=%p response=%v", chooserCalls, used, msg.Response)
	}
	if pending == nil || pending.cacheKey.networkType.L4Proto != consts.L4ProtoStr_TCP {
		t.Fatalf("pending cache key did not use TCP: %#v", pending)
	}
	if upstream.Scheme != dns.UpstreamScheme_TCP_UDP {
		t.Fatalf("fallback mutated resolved upstream scheme to %q", upstream.Scheme)
	}
}

func TestDNSFallbackRetriesTruncatedUDPResponseWithOriginalQuery(t *testing.T) {
	udpArg := fallbackTestArgument(consts.L4ProtoStr_UDP, "192.0.2.1:53")
	tcpArg := fallbackTestArgument(consts.L4ProtoStr_TCP, "192.0.2.2:53")
	c := fallbackTestController(t, func(*dns.Upstream) (*dialArgument, error) { return tcpArg, nil })
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP, Hostname: "dns.example", Port: 53}
	cacheFallbackForwarder(c, upstream, udpArg, &scriptedDNSForwarder{forward: func(_ context.Context, msg *dnsmessage.Msg) error {
		response := new(dnsmessage.Msg)
		response.SetReply(msg)
		response.Truncated = true
		response.Answer = []dnsmessage.RR{testARecord("example.com.", "192.0.2.10")}
		*msg = *response
		return nil
	}})
	cacheFallbackForwarder(c, upstream, tcpArg, &scriptedDNSForwarder{forward: func(_ context.Context, msg *dnsmessage.Msg) error {
		if msg.Response || msg.Truncated || len(msg.Answer) != 0 {
			t.Fatalf("TCP fallback received truncated UDP response: %+v", msg)
		}
		response := new(dnsmessage.Msg)
		response.SetReply(msg)
		response.Answer = []dnsmessage.RR{testARecord("example.com.", "192.0.2.20")}
		*msg = *response
		return nil
	}})

	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	_, used, err := c.dialSendWithFallback(
		context.Background(), msg, &udpRequest{}, upstream, udpArg,
		fallbackTestKey(t, msg), true, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if used != tcpArg || !msg.Response || msg.Truncated || len(msg.Answer) != 1 {
		t.Fatalf("unexpected final response: used=%p message=%+v", used, msg)
	}
	if got := netip.MustParseAddr(msg.Answer[0].(*dnsmessage.A).A.String()); got != netip.MustParseAddr("192.0.2.20") {
		t.Fatalf("final answer = %v, want TCP answer", got)
	}
}

func TestDNSFallbackPreservesUncacheableTruncatedResponseWhenTCPFails(t *testing.T) {
	tcpErr := errors.New("TCP unavailable")
	udpArg := fallbackTestArgument(consts.L4ProtoStr_UDP, "192.0.2.1:53")
	tcpArg := fallbackTestArgument(consts.L4ProtoStr_TCP, "192.0.2.2:53")
	c, registry, _ := newTestDnsController(t, nil)
	c.bestDialerChooser = func(*udpRequest, *dns.Upstream) (*dialArgument, error) { return tcpArg, nil }
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP, Hostname: "dns.example", Port: 53}
	cacheFallbackForwarder(c, upstream, udpArg, &scriptedDNSForwarder{forward: func(_ context.Context, msg *dnsmessage.Msg) error {
		response := new(dnsmessage.Msg)
		response.SetReply(msg)
		response.Truncated = true
		response.Answer = []dnsmessage.RR{testARecord("example.com.", "192.0.2.10")}
		*msg = *response
		return nil
	}})
	cacheFallbackForwarder(c, upstream, tcpArg, &scriptedDNSForwarder{forward: func(context.Context, *dnsmessage.Msg) error {
		return tcpErr
	}})

	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	pending, used, err := c.dialSendWithFallback(
		context.Background(), msg, &udpRequest{}, upstream, udpArg,
		fallbackTestKey(t, msg), true, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if used != udpArg || pending == nil || !msg.Response || !msg.Truncated || len(msg.Answer) != 1 {
		t.Fatalf("truncated UDP response was not preserved: used=%p pending=%#v message=%+v", used, pending, msg)
	}
	c.finalizeAcceptedResponse(msg, pending)
	if c.dnsCache.Len() != 0 || registry.Size() != 0 {
		t.Fatalf("truncated response entered cache or registry: cache=%d registry=%d", c.dnsCache.Len(), registry.Size())
	}
}

func TestDNSFallbackSkipsQueriesThatAreNotReplaySafe(t *testing.T) {
	udpErr := errors.New("UDP unavailable")
	udpArg := fallbackTestArgument(consts.L4ProtoStr_UDP, "192.0.2.1:53")
	chooserCalls := 0
	c := fallbackTestController(t, func(*dns.Upstream) (*dialArgument, error) {
		chooserCalls++
		return fallbackTestArgument(consts.L4ProtoStr_TCP, "192.0.2.2:53"), nil
	})
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP, Hostname: "dns.example", Port: 53}
	cacheFallbackForwarder(c, upstream, udpArg, &scriptedDNSForwarder{forward: func(context.Context, *dnsmessage.Msg) error {
		return udpErr
	}})

	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	msg.Opcode = dnsmessage.OpcodeUpdate
	key, replaySafe, cacheable := makeDNSQueryKey(msg, queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA})
	if replaySafe || cacheable {
		t.Fatal("UPDATE query was classified as replay-safe")
	}
	_, used, err := c.dialSendWithFallback(
		context.Background(), msg, &udpRequest{}, upstream, udpArg,
		key, replaySafe, cacheable, true,
	)
	if !errors.Is(err, udpErr) || used != udpArg {
		t.Fatalf("unsafe query result = (%p, %v), want primary UDP error", used, err)
	}
	if chooserCalls != 0 {
		t.Fatalf("fallback chooser called %d times for unsafe query", chooserCalls)
	}
}

func TestDNSFallbackBlackholedUDPLeavesCallerBudgetForTCP(t *testing.T) {
	udpArg := fallbackTestArgument(consts.L4ProtoStr_UDP, "192.0.2.1:53")
	tcpArg := fallbackTestArgument(consts.L4ProtoStr_TCP, "192.0.2.2:53")
	c := fallbackTestController(t, func(*dns.Upstream) (*dialArgument, error) { return tcpArg, nil })
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP, Hostname: "dns.example", Port: 53}

	var udpDeadline, tcpDeadline time.Time
	cacheFallbackForwarder(c, upstream, udpArg, &scriptedDNSForwarder{forward: func(ctx context.Context, _ *dnsmessage.Msg) error {
		udpDeadline, _ = ctx.Deadline()
		<-ctx.Done()
		return ctx.Err()
	}})
	cacheFallbackForwarder(c, upstream, tcpArg, &scriptedDNSForwarder{forward: func(ctx context.Context, msg *dnsmessage.Msg) error {
		tcpDeadline, _ = ctx.Deadline()
		response := new(dnsmessage.Msg)
		response.SetReply(msg)
		*msg = *response
		return nil
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	outerDeadline, _ := ctx.Deadline()
	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	_, used, err := c.dialSendWithFallback(
		ctx, msg, &udpRequest{}, upstream, udpArg,
		fallbackTestKey(t, msg), true, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if used != tcpArg || !msg.Response {
		t.Fatalf("blackholed UDP did not fall back to TCP: used=%p message=%+v", used, msg)
	}
	if udpDeadline.IsZero() || !udpDeadline.Before(outerDeadline) {
		t.Fatalf("UDP phase did not reserve caller budget: UDP=%v outer=%v", udpDeadline, outerDeadline)
	}
	if !tcpDeadline.Equal(outerDeadline) {
		t.Fatalf("TCP did not retain caller deadline: TCP=%v outer=%v", tcpDeadline, outerDeadline)
	}
}

func TestDNSFallbackHonorsParentCancellationDuringTCPRetry(t *testing.T) {
	udpErr := errors.New("UDP unavailable")
	udpArg := fallbackTestArgument(consts.L4ProtoStr_UDP, "192.0.2.1:53")
	tcpArg := fallbackTestArgument(consts.L4ProtoStr_TCP, "192.0.2.2:53")
	c := fallbackTestController(t, func(*dns.Upstream) (*dialArgument, error) { return tcpArg, nil })
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP, Hostname: "dns.example", Port: 53}
	tcpStarted := make(chan struct{})
	cacheFallbackForwarder(c, upstream, udpArg, &scriptedDNSForwarder{forward: func(context.Context, *dnsmessage.Msg) error {
		return udpErr
	}})
	cacheFallbackForwarder(c, upstream, tcpArg, &scriptedDNSForwarder{forward: func(ctx context.Context, _ *dnsmessage.Msg) error {
		close(tcpStarted)
		<-ctx.Done()
		return ctx.Err()
	}})

	ctx, cancel := context.WithCancel(context.Background())
	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	done := make(chan error, 1)
	go func() {
		_, _, err := c.dialSendWithFallback(
			ctx, msg, &udpRequest{}, upstream, udpArg,
			fallbackTestKey(t, msg), true, true, true,
		)
		done <- err
	}()
	select {
	case <-tcpStarted:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("TCP fallback did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fallback error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback ignored parent cancellation")
	}
}
