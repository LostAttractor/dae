/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type failDnsForwarder struct {
	t *testing.T
}

type closeTrackingDnsForwarder struct {
	closed chan struct{}
}

type cancelAwareDnsForwarder struct {
	started chan struct{}
	closed  chan struct{}
}

type countingDnsForwarder struct {
	closeCalls int
}

func (f *countingDnsForwarder) ForwardDNS(context.Context, *dnsmessage.Msg) error { return nil }
func (f *countingDnsForwarder) Close() error {
	f.closeCalls++
	return nil
}

func (f *cancelAwareDnsForwarder) ForwardDNS(ctx context.Context, _ *dnsmessage.Msg) error {
	close(f.started)
	<-ctx.Done()
	return ctx.Err()
}

func (f *cancelAwareDnsForwarder) Close() error {
	close(f.closed)
	return nil
}

func (f *closeTrackingDnsForwarder) ForwardDNS(context.Context, *dnsmessage.Msg) error { return nil }
func (f *closeTrackingDnsForwarder) Close() error {
	close(f.closed)
	return nil
}

func (f failDnsForwarder) ForwardDNS(context.Context, *dnsmessage.Msg) error {
	f.t.Fatal("cached response unexpectedly reached the forwarder")
	return nil
}

func testAAAARecord(name string, ip string) *dnsmessage.AAAA {
	return &dnsmessage.AAAA{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeAAAA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		AAAA: net.ParseIP(ip),
	}
}

// newTestDnsController builds a DnsController wired to a fake-kernel
// registry. routing/dialer are nil: registerAnswers and the cache helpers never
// touch them.
func newTestDnsController(t *testing.T, fixedDomainTtl map[string]int) (*DnsController, *DomainRegistry, *fakeKernelDomainMaps) {
	t.Helper()
	registry, fake := newTestRegistry(16, 16, 10*time.Second)
	c, err := NewDnsController(nil, &DnsControllerOption{
		MatchBitmap: func(fqdn string) []uint32 {
			return testBitmap(0)
		},
		DomainRegistry: registry,
		FixedDomainTtl: fixedDomainTtl,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, registry, fake
}

func TestRegisterAnswersByQtype(t *testing.T) {
	c, registry, fake := newTestDnsController(t, nil)
	qiA := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	qiAAAA := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeAAAA}
	ip4 := netip.MustParseAddr("1.2.3.4")
	ip6 := netip.MustParseAddr("2606:4700::1234")

	c.registerAnswers(qiA, []dnsmessage.RR{testARecord("example.com.", "1.2.3.4")})
	c.registerAnswers(qiAAAA, []dnsmessage.RR{testAAAARecord("example.com.", "2606:4700::1234")})

	// Records land under their own family's key.
	if got := registry.Lookup(qiA); len(got) != 1 || got[0] != ip4 {
		t.Fatalf("A record should verify under the A key: %v", got)
	}
	if got := registry.Lookup(qiAAAA); len(got) != 1 || got[0] != ip6 {
		t.Fatalf("AAAA record should verify under the AAAA key: %v", got)
	}
	// The kernel maps key by IP only: both addresses are admitted.
	if !fake.has(ip4) || !fake.has(ip6) {
		t.Fatalf("both addresses should enter the kernel maps: %v", fake.bump)
	}
	checkInvariants(t, registry, fake)
}

func TestRegisterAnswersKeepsPerAddressTtl(t *testing.T) {
	c, registry, fake := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	short := testARecord("example.com.", "1.1.1.1")
	short.Hdr.Ttl = 30
	long := testARecord("example.com.", "2.2.2.2")
	long.Hdr.Ttl = 120
	start := time.Now()

	c.registerAnswers(qi, []dnsmessage.RR{short, long})
	shortExpiry := registry.byName[qi][netip.MustParseAddr("1.1.1.1")].expiry
	longExpiry := registry.byName[qi][netip.MustParseAddr("2.2.2.2")].expiry
	if d := shortExpiry.Sub(start); d < 25*time.Second || d > 35*time.Second {
		t.Errorf("short-lived IP should keep its own registry TTL: %v", d)
	}
	if d := longExpiry.Sub(start); d < 115*time.Second || d > 125*time.Second {
		t.Errorf("long-lived IP should keep its own registry TTL: %v", d)
	}
	checkInvariants(t, registry, fake)
}

func TestRegisterAnswersSkipsNonAddressAnswers(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}

	c.registerAnswers(qi, []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr:    dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
			Target: "cdn.example.",
		},
		testARecord("example.com.", "0.0.0.0"), // unspecified
	})
	if registry.Size() != 0 {
		t.Fatalf("CNAME and unspecified addresses must not be registered: size=%v", registry.Size())
	}
}

func TestRegisterAnswersFixedTtlSemantics(t *testing.T) {
	fixed := map[string]int{
		"pinned.com.":  30,
		"nocache.com.": 0,
	}
	c, registry, fake := newTestDnsController(t, fixed)

	// fixed_ttl is the effective registration TTL as well as the response
	// cache TTL. The registry still applies its MinDomainTTL floor.
	start := time.Now()
	qiPinned := queryInfo{qname: "pinned.com.", qtype: dnsmessage.TypeA}
	ipPinned := netip.MustParseAddr("1.1.1.1")
	c.registerAnswers(qiPinned, []dnsmessage.RR{testARecord("pinned.com.", "1.1.1.1")})
	r := registry.byName[qiPinned][ipPinned]
	if r == nil {
		t.Fatalf("pinned.com. should be registered")
	}
	if d := r.expiry.Sub(start); d < 25*time.Second || d > 35*time.Second {
		t.Errorf("registration lifetime should follow fixed_ttl (30s): %v", d)
	}
	if !fake.has(ipPinned) {
		t.Errorf("pinned.com. should be admitted to the kernel maps")
	}

	// fixed_ttl=0 disables only the DNS response cache. The registration still
	// enters the kernel for at least MinDomainTTL.
	qiNocache := queryInfo{qname: "nocache.com.", qtype: dnsmessage.TypeA}
	ipNocache := netip.MustParseAddr("2.2.2.2")
	c.registerAnswers(qiNocache, []dnsmessage.RR{testARecord("nocache.com.", "2.2.2.2")})
	if !fake.has(ipNocache) {
		t.Errorf("fixed_ttl=0 must still write the kernel maps")
	}
	if got := registry.Lookup(qiNocache); len(got) != 1 || got[0] != ipNocache {
		t.Errorf("fixed_ttl=0 record should still verify: %v", got)
	}
	r = registry.byName[qiNocache][ipNocache]
	if d := r.expiry.Sub(start); d < 5*time.Second || d > 15*time.Second {
		t.Errorf("fixed_ttl=0 registration lifetime should be floored by MinDomainTTL: %v", d)
	}
	checkInvariants(t, registry, fake)
}

func TestUpdateDnsCacheFixedDomain(t *testing.T) {
	fixed := map[string]int{"pinned.com.": 30, "nocache.com.": 0}
	c, _, _ := newTestDnsController(t, fixed)
	key := dnsCacheKey{queryInfo: queryInfo{qname: "pinned.com.", qtype: dnsmessage.TypeA}}

	// The record says 3600s, fixed_ttl says 30s: the response cache honors
	// fixed_ttl (its only sphere of influence).
	answer := testARecord("pinned.com.", "1.1.1.1")
	answer.Hdr.Ttl = 3600
	c.UpdateDnsCache(key, "pinned.com.", []dnsmessage.RR{answer})
	caches := c.dnsCache.Get(key)
	if len(caches) != 1 {
		t.Fatalf("expected one cached answer: %v", len(caches))
	}
	if d := time.Until(caches[0].Deadline); d < 25*time.Second || d > 31*time.Second {
		t.Errorf("response cache should honor fixed_ttl (30s), not the record ttl (3600s): %v", d)
	}

	noCacheKey := dnsCacheKey{queryInfo: queryInfo{qname: "nocache.com.", qtype: dnsmessage.TypeA}}
	c.UpdateDnsCache(noCacheKey, "nocache.com.", []dnsmessage.RR{testARecord("nocache.com.", "2.2.2.2")})
	if c.dnsCache.Len() != 1 {
		t.Fatalf("fixed_ttl=0 entry should not occupy the cache: len=%d", c.dnsCache.Len())
	}
	if caches := c.dnsCache.Get(noCacheKey); caches != nil {
		t.Fatalf("fixed_ttl=0 response must be expired immediately: %v", caches)
	}
}

func TestUpdateDnsCacheKeepsPerAnswerDeadlines(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	key := dnsCacheKey{queryInfo: queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}}
	short := testARecord("example.com.", "1.1.1.1")
	short.Hdr.Ttl = 30
	long := testARecord("example.com.", "2.2.2.2")
	long.Hdr.Ttl = 120
	start := time.Now()

	c.UpdateDnsCache(key, "example.com.", []dnsmessage.RR{short, long})
	caches := c.dnsCache.Get(key)
	if len(caches) != 2 {
		t.Fatalf("expected both answers: %v", caches)
	}
	deadlines := make(map[string]time.Time)
	for _, cache := range caches {
		a := cache.Answer.(*dnsmessage.A)
		deadlines[net.IP(a.A).String()] = cache.Deadline
	}
	if d := deadlines["1.1.1.1"].Sub(start); d < 25*time.Second || d > 35*time.Second {
		t.Errorf("short-lived IP should keep its own TTL: %v", d)
	}
	if d := deadlines["2.2.2.2"].Sub(start); d < 115*time.Second || d > 125*time.Second {
		t.Errorf("long-lived IP should keep its own TTL: %v", d)
	}
}

func TestApplyFixedTtlToResponse(t *testing.T) {
	c, _, _ := newTestDnsController(t, map[string]int{
		"pinned.com.":  30,
		"nocache.com.": 0,
	})
	pinned := testARecord("pinned.com.", "1.1.1.1")
	pinned.Hdr.Ttl = 3600
	c.applyFixedTTL("pinned.com.", []dnsmessage.RR{pinned})
	if pinned.Hdr.Ttl != 30 {
		t.Fatalf("returned response should use fixed_ttl: %v", pinned.Hdr.Ttl)
	}

	nocache := testARecord("nocache.com.", "2.2.2.2")
	nocache.Hdr.Ttl = 3600
	c.applyFixedTTL("nocache.com.", []dnsmessage.RR{nocache})
	if nocache.Hdr.Ttl != 0 {
		t.Fatalf("fixed_ttl=0 response should return TTL 0: %v", nocache.Hdr.Ttl)
	}
}

func TestCachedFixedTtlResponseKeepsRemainingLifetime(t *testing.T) {
	c, registry, _ := newTestDnsController(t, map[string]int{"pinned.com.": 30})
	qi := queryInfo{qname: "pinned.com.", qtype: dnsmessage.TypeA}
	ip := netip.MustParseAddr("1.1.1.1")

	upstreamResponse := &dnsmessage.Msg{Answer: []dnsmessage.RR{testARecord("pinned.com.", ip.String())}}
	upstreamResponse.Answer[0].Header().Ttl = 3600
	c.finalizeAcceptedResponse(qi, upstreamResponse, false)
	registration := registry.byName[qi][ip]
	if registration == nil {
		t.Fatal("upstream response should register its address")
	}
	registryDeadline := registration.expiry
	if got := upstreamResponse.Answer[0].Header().Ttl; got != 30 {
		t.Fatalf("fresh upstream response should apply fixed TTL: %v", got)
	}

	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "8.8.8.8", Port: 53}
	dialArg := &dialArgument{}
	forwarderKey := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArg}
	cacheKey := dnsCacheKey{queryInfo: qi, dnsForwarderKey: forwarderKey}
	c.dnsForwarderCache.Store(forwarderKey, failDnsForwarder{t: t})
	c.dnsCache.ReplaceDeadline(cacheKey, upstreamResponse.Answer, time.Now().Add(5*time.Second))
	cachedResponse := &dnsmessage.Msg{Question: []dnsmessage.Question{{Name: qi.qname, Qtype: qi.qtype}}}
	fromCache, err := c.dialSend(context.Background(), cachedResponse, upstream, dialArg, qi, true)
	if err != nil {
		t.Fatal(err)
	}
	if !fromCache {
		t.Fatal("dialSend should identify a cached response")
	}
	if len(cachedResponse.Answer) != 1 {
		t.Fatalf("expected one cached answer: %v", cachedResponse.Answer)
	}
	remainingTTL := cachedResponse.Answer[0].Header().Ttl
	if remainingTTL == 0 || remainingTTL > 5 {
		t.Fatalf("cached response should expose its remaining TTL: %v", remainingTTL)
	}

	c.finalizeAcceptedResponse(qi, cachedResponse, fromCache)
	if got := cachedResponse.Answer[0].Header().Ttl; got != remainingTTL {
		t.Fatalf("fixed TTL must not restart on a cache hit: got %v, want %v", got, remainingTTL)
	}
	if got := registry.byName[qi][ip].expiry; !got.Equal(registryDeadline) {
		t.Fatalf("cache hit must not refresh the registry: got %v, want %v", got, registryDeadline)
	}
}

func TestRegisterAnswersNoExpiryIgnoresFixedTtl(t *testing.T) {
	c, registry, fake := newTestDnsController(t, map[string]int{"resolver.example.": 0})
	qi := queryInfo{qname: "resolver.example.", qtype: dnsmessage.TypeA}
	ip := netip.MustParseAddr("1.1.1.1")
	c.registerAnswersNoExpiry(qi, []dnsmessage.RR{testARecord(qi.qname, ip.String())})

	registration := registry.byName[qi][ip]
	if registration == nil || !fake.has(ip) {
		t.Fatal("synthetic upstream address should be registered in the kernel maps")
	}
	if !registration.expiry.IsZero() {
		t.Fatalf("synthetic upstream address should have no expiry: %+v", registration)
	}
	checkInvariants(t, registry, fake)
}

func TestRegisterAnswersNoExpiryAfterCloseIsNoop(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	qi := queryInfo{qname: "resolver.example.", qtype: dnsmessage.TypeA}
	c.registerAnswersNoExpiry(qi, []dnsmessage.RR{testARecord(qi.qname, "1.1.1.1")})
	if registry.Size() != 0 {
		t.Fatal("synthetic registration mutated the registry after Close")
	}
}

func TestSelectDnsForwarderOwnership(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	ephemeral := &countingDnsForwarder{}
	selected, release := c.selectDnsForwarder(dnsForwarderKey{}, ephemeral, false)
	if selected != ephemeral {
		t.Fatal("ephemeral forwarder was replaced")
	}
	release()
	if ephemeral.closeCalls != 1 {
		t.Fatalf("ephemeral forwarder close calls = %d, want 1", ephemeral.closeCalls)
	}

	key := dnsForwarderKey{upstream: "udp://resolver.example:53"}
	first := &countingDnsForwarder{}
	selected, release = c.selectDnsForwarder(key, first, true)
	release()
	if selected != first || first.closeCalls != 0 {
		t.Fatal("new cached forwarder was not retained")
	}
	loser := &countingDnsForwarder{}
	selected, release = c.selectDnsForwarder(key, loser, true)
	release()
	if selected != first || loser.closeCalls != 1 {
		t.Fatal("LoadOrStore loser was not closed")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if first.closeCalls != 1 {
		t.Fatalf("cached forwarder close calls = %d, want 1", first.closeCalls)
	}
}

func TestHandleAfterClose(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	msg := testQuery("example.com.", dnsmessage.TypeA, 1)
	if err := c.Handle(msg, nil); err != nil {
		t.Fatal(err)
	}
	if registry.Size() != 0 {
		t.Fatalf("Handle after Close must be a no-op: size=%v", registry.Size())
	}
}

func TestDnsControllerCloseWaitsForInFlightRequests(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	forwarder := &closeTrackingDnsForwarder{closed: make(chan struct{})}
	c.dnsForwarderCache.Store(dnsForwarderKey{}, forwarder)
	if !c.beginRequest() {
		t.Fatal("open controller rejected request registration")
	}

	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	deadline := time.After(time.Second)
	for c.closed.Err() == nil {
		select {
		case <-deadline:
			t.Fatal("Close did not cancel the controller")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-forwarder.closed:
		t.Fatal("forwarder closed while a request was still in flight")
	default:
	}

	c.endRequest()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after the request ended")
	}
	select {
	case <-forwarder.closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not release the forwarder")
	}
	if c.beginRequest() {
		t.Fatal("closed controller accepted a new request")
	}
}

func TestDnsControllerCloseCancelsInFlightForwarder(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "8.8.8.8", Port: 53}
	dialArg := &dialArgument{
		networkType: common.NetworkType{L4Proto: consts.L4ProtoStr_UDP},
		Target:      netip.MustParseAddrPort("8.8.8.8:53"),
	}
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArg}
	forwarder := &cancelAwareDnsForwarder{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	c.dnsForwarderCache.Store(key, forwarder)
	if !c.beginRequest() {
		t.Fatal("open controller rejected request registration")
	}
	requestDone := make(chan error, 1)
	go func() {
		defer c.endRequest()
		_, err := c.dialSend(c.closed, testQuery("example.com.", dnsmessage.TypeA, 1), upstream, dialArg,
			queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, true)
		requestDone <- err
	}()
	<-forwarder.started

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-requestDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("forwarder error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the in-flight forwarder")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after cancellation")
	}
	select {
	case <-forwarder.closed:
	default:
		t.Fatal("Close did not release the forwarder")
	}
}

func TestAcceptedResponseRegistersDuringClose(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	if !c.beginRequest() {
		t.Fatal("open controller rejected request registration")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	for c.closed.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	msg := &dnsmessage.Msg{Answer: []dnsmessage.RR{testARecord(qi.qname, "1.2.3.4")}}
	c.finalizeAcceptedResponse(qi, msg, false)
	c.endRequest()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if got := registry.Lookup(qi); len(got) != 1 || got[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("accepted response was not registered during Close: %v", got)
	}
}
