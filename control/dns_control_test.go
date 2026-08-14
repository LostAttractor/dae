/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
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

func waitForDnsFlightParticipants(t *testing.T, c *DnsController, key dnsFlightKey, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.dnsFlightMu.Lock()
		flight := c.dnsFlights[key]
		got := 0
		if flight != nil {
			got = flight.participantCount
		}
		c.dnsFlightMu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("flight participants did not reach %d", want)
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

func (f failDnsForwarder) Close() error { return nil }

type blockingDnsForwarder struct {
	calls     atomic.Int32
	closes    atomic.Int32
	started   chan struct{}
	closed    chan struct{}
	startOnce atomic.Bool
}

func (f *blockingDnsForwarder) ForwardDNS(_ context.Context, _ *dnsmessage.Msg) error {
	f.calls.Add(1)
	if f.startOnce.CompareAndSwap(false, true) {
		close(f.started)
	}
	<-f.closed
	return net.ErrClosed
}

func (f *blockingDnsForwarder) Close() error {
	if f.closes.Add(1) == 1 {
		close(f.closed)
	}
	return nil
}

// newTestDnsController builds a DnsController wired to a fake-kernel
// registry. routing/dialer are nil because response planning and publication
// do not use them.
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
	t.Cleanup(func() { _ = c.Close() })
	return c, registry, fake
}

func registerTestDNSResponse(c *DnsController, qi queryInfo, answers []dnsmessage.RR) {
	c.registerResponsePlan(c.planDNSResponse(qi, answers), time.Now())
}

func cacheTestDNSResponse(c *DnsController, key dnsCacheKey, answers []dnsmessage.RR) {
	c.cacheResponsePlan(key, c.planDNSResponse(key.queryInfo, answers))
}

func TestDnsControllerReturnsFormerrForMultipleQuestions(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	sent := make(chan []byte, 1)
	c.sendPacket = func(data []byte, _, _ netip.AddrPort) error {
		sent <- append([]byte(nil), data...)
		return nil
	}
	msg := testDNSQuery("one.example.", dnsmessage.TypeA, 7)
	for len(msg.Question) < 64 {
		msg.Question = append(msg.Question, dnsmessage.Question{
			Name: "a-long-extra-question.example.", Qtype: dnsmessage.TypeAAAA, Qclass: dnsmessage.ClassINET,
		})
	}
	if err := c.Handle(msg, &udpRequest{}); err != nil {
		t.Fatal(err)
	}

	select {
	case data := <-sent:
		if len(data) > dnsmessage.MinMsgSize {
			t.Fatalf("FORMERR response exceeds classic UDP DNS size: %d", len(data))
		}
		var response dnsmessage.Msg
		if err := response.Unpack(data); err != nil {
			t.Fatal(err)
		}
		if !response.Response || response.Rcode != dnsmessage.RcodeFormatError {
			t.Fatalf("multiple-question response: QR=%v rcode=%v", response.Response, response.Rcode)
		}
	case <-time.After(time.Second):
		t.Fatal("multiple-question request did not receive FORMERR")
	}
}

func TestDnsControllerClosedHandleIgnoresMalformedMessages(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	response := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	response.Response = true
	if err := c.Handle(response, &udpRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Handle(&dnsmessage.Msg{}, &udpRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterAnswersByQtype(t *testing.T) {
	c, registry, fake := newTestDnsController(t, nil)
	qiA := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	qiAAAA := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeAAAA}
	ip4 := netip.MustParseAddr("1.2.3.4")
	ip6 := netip.MustParseAddr("2606:4700::1234")

	registerTestDNSResponse(c, qiA, []dnsmessage.RR{testARecord("example.com.", "1.2.3.4")})
	registerTestDNSResponse(c, qiAAAA, []dnsmessage.RR{testAAAARecord("example.com.", "2606:4700::1234")})

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

func TestRegisterAnswersNormalizesRRSetTtl(t *testing.T) {
	c, registry, fake := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	short := testARecord("example.com.", "1.1.1.1")
	short.Hdr.Ttl = 30
	long := testARecord("example.com.", "2.2.2.2")
	long.Hdr.Ttl = 120
	start := time.Now()

	registerTestDNSResponse(c, qi, []dnsmessage.RR{short, long})
	shortExpiry := registry.byName[qi][netip.MustParseAddr("1.1.1.1")].effectiveExpiry()
	longExpiry := registry.byName[qi][netip.MustParseAddr("2.2.2.2")].effectiveExpiry()
	if d := shortExpiry.Sub(start); d < 25*time.Second || d > 35*time.Second {
		t.Errorf("short-lived IP should keep its own registry TTL: %v", d)
	}
	if d := longExpiry.Sub(start); d < 25*time.Second || d > 35*time.Second {
		t.Errorf("one RRset should use its shortest TTL: %v", d)
	}
	checkInvariants(t, registry, fake)
}

func TestRegisterAnswersSkipsNonAddressAnswers(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}

	registerTestDNSResponse(c, qi, []dnsmessage.RR{
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
	registerTestDNSResponse(c, qiPinned, []dnsmessage.RR{testARecord("pinned.com.", "1.1.1.1")})
	r := registry.byName[qiPinned][ipPinned]
	if r == nil {
		t.Fatalf("pinned.com. should be registered")
	}
	if d := r.effectiveExpiry().Sub(start); d < 25*time.Second || d > 35*time.Second {
		t.Errorf("registration lifetime should follow fixed_ttl (30s): %v", d)
	}
	if !fake.has(ipPinned) {
		t.Errorf("pinned.com. should be admitted to the kernel maps")
	}

	// fixed_ttl=0 disables only the DNS response cache. The registration still
	// enters the kernel for at least MinDomainTTL.
	qiNocache := queryInfo{qname: "nocache.com.", qtype: dnsmessage.TypeA}
	ipNocache := netip.MustParseAddr("2.2.2.2")
	registerTestDNSResponse(c, qiNocache, []dnsmessage.RR{testARecord("nocache.com.", "2.2.2.2")})
	if !fake.has(ipNocache) {
		t.Errorf("fixed_ttl=0 must still write the kernel maps")
	}
	if got := registry.Lookup(qiNocache); len(got) != 1 || got[0] != ipNocache {
		t.Errorf("fixed_ttl=0 record should still verify: %v", got)
	}
	r = registry.byName[qiNocache][ipNocache]
	if d := r.effectiveExpiry().Sub(start); d < 5*time.Second || d > 15*time.Second {
		t.Errorf("fixed_ttl=0 registration lifetime should be floored by MinDomainTTL: %v", d)
	}
	checkInvariants(t, registry, fake)
}

func TestResponseCacheFixedDomain(t *testing.T) {
	fixed := map[string]int{"pinned.com.": 30, "nocache.com.": 0}
	c, _, _ := newTestDnsController(t, fixed)
	key := dnsCacheKey{queryInfo: queryInfo{qname: "pinned.com.", qtype: dnsmessage.TypeA}}

	// The record says 3600s, fixed_ttl says 30s: the response cache honors
	// fixed_ttl (its only sphere of influence).
	answer := testARecord("pinned.com.", "1.1.1.1")
	answer.Hdr.Ttl = 3600
	cacheTestDNSResponse(c, key, []dnsmessage.RR{answer})
	caches := getTestDNSCache(c.dnsCache, key)
	if len(caches) != 1 {
		t.Fatalf("expected one cached answer: %v", len(caches))
	}
	if d := time.Until(caches[0].Deadline); d < 25*time.Second || d > 31*time.Second {
		t.Errorf("response cache should honor fixed_ttl (30s), not the record ttl (3600s): %v", d)
	}

	noCacheKey := dnsCacheKey{queryInfo: queryInfo{qname: "nocache.com.", qtype: dnsmessage.TypeA}}
	cacheTestDNSResponse(c, noCacheKey, []dnsmessage.RR{testARecord("nocache.com.", "2.2.2.2")})
	if caches := getTestDNSCache(c.dnsCache, noCacheKey); caches != nil {
		t.Fatalf("fixed_ttl=0 response must be expired immediately: %v", caches)
	}
}

func TestDNSFlightCoalescesTtlZeroDuplicates(t *testing.T) {
	c, _, _ := newTestDnsController(t, map[string]int{"example.com.": 0})
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	key := testDNSFlightKey(qi, "ttl-zero")
	leaderMsg := testDNSQuery("ExAmPlE.com.", qi.qtype, 1)
	followerMsg := testDNSQuery("eXaMpLe.com.", qi.qtype, 2)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	leaderDone := make(chan error, 1)
	go func() {
		leaderDone <- c.shareDNSResult(context.Background(), key, leaderMsg, func() error {
			calls.Add(1)
			close(started)
			<-release
			response := new(dnsmessage.Msg)
			response.SetReply(leaderMsg)
			response.Answer = []dnsmessage.RR{testARecord(qi.qname, "1.2.3.4")}
			*leaderMsg = *response
			c.finalizeAcceptedResponse(leaderMsg, &pendingDNSResponse{
				cacheKey: dnsCacheKey{queryInfo: qi, variant: key.query.variant}, register: true, receivedAt: time.Now(),
			})
			return nil
		})
	}()
	<-started
	followerDone := make(chan error, 1)
	var followerResolved atomic.Bool
	go func() {
		followerDone <- c.shareDNSResult(context.Background(), key, followerMsg, func() error {
			followerResolved.Store(true)
			return nil
		})
	}()
	waitForDnsFlightParticipants(t, c, key, 2)
	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatal(err)
	}
	if err := <-followerDone; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("TTL=0 flight resolutions = %d, want 1", calls.Load())
	}
	if followerResolved.Load() {
		t.Fatal("follower unexpectedly resolved upstream")
	}
	if !leaderMsg.Response || !followerMsg.Response || followerMsg.Id != 2 || followerMsg.Question[0].Name != "eXaMpLe.com." {
		t.Fatalf("TTL=0 response fan-out lost client identity: %+v", followerMsg)
	}
	if c.dnsCache.Len() != 0 {
		t.Fatalf("TTL=0 answers occupied cache: len=%d", c.dnsCache.Len())
	}
}

func TestDNSFlightCoalescesUpstreamErrors(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	key := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "error")
	wantErr := errors.New("upstream failure")
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	leaderDone := make(chan error, 1)
	go func() {
		leaderDone <- c.shareDNSResult(context.Background(), key, testDNSQuery("example.com.", dnsmessage.TypeA, 1), func() error {
			calls.Add(1)
			close(started)
			<-release
			return wantErr
		})
	}()
	<-started
	followerDone := make(chan error, 1)
	var followerResolved atomic.Bool
	go func() {
		followerDone <- c.shareDNSResult(context.Background(), key, testDNSQuery("example.com.", dnsmessage.TypeA, 2), func() error {
			followerResolved.Store(true)
			return nil
		})
	}()
	waitForDnsFlightParticipants(t, c, key, 2)
	close(release)
	if err := <-leaderDone; !errors.Is(err, wantErr) {
		t.Fatalf("leader error = %v, want %v", err, wantErr)
	}
	if err := <-followerDone; !errors.Is(err, wantErr) {
		t.Fatalf("follower error = %v, want %v", err, wantErr)
	}
	if calls.Load() != 1 {
		t.Fatalf("failed flight resolutions = %d, want 1", calls.Load())
	}
	if followerResolved.Load() {
		t.Fatal("follower unexpectedly resolved upstream")
	}
}

func TestDNSFlightParticipantLimit(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	key := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "")
	flight, leader, err := c.joinDNSFlight(key)
	if err != nil || !leader || flight == nil {
		t.Fatal("first participant was not admitted as leader")
	}
	for i := 1; i < consts.MaxDnsFlightParticipants; i++ {
		joined, leader, err := c.joinDNSFlight(key)
		if err != nil || leader || joined != flight {
			t.Fatalf("participant %d was not admitted as follower", i+1)
		}
	}
	if joined, _, err := c.joinDNSFlight(key); err != nil || joined != nil {
		t.Fatal("participant above the flight limit was admitted")
	}
	c.leaveDNSFlight(key, flight)
	if joined, leader, err := c.joinDNSFlight(key); err != nil || leader || joined != flight {
		t.Fatal("a departed waiter did not release its flight slot")
	}
	c.finishDNSFlight(key, flight, nil, nil)
}

func TestDNSFlightDropsStaleDuplicateWaiter(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	c.dnsDuplicateWaitTimeout = 20 * time.Millisecond
	key := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "")
	flight, leader, err := c.joinDNSFlight(key)
	if err != nil || !leader {
		t.Fatal("leader was not admitted")
	}
	follower, followerLeader, err := c.joinDNSFlight(key)
	if err != nil || followerLeader || follower != flight {
		t.Fatal("follower did not join")
	}
	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 2)
	if err := c.waitDNSFlight(context.Background(), key, follower, msg); err != nil {
		t.Fatal(err)
	}
	if msg.Response {
		t.Fatal("stale duplicate unexpectedly received a response")
	}
	c.finishDNSFlight(key, flight, nil, nil)
}

func TestDNSFlightCompletionWinsTimeoutRace(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	key := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "")
	flight, leader, err := c.joinDNSFlight(key)
	if err != nil || !leader {
		t.Fatal("leader was not admitted")
	}
	follower, followerLeader, err := c.joinDNSFlight(key)
	if err != nil || followerLeader || follower != flight {
		t.Fatal("follower did not join")
	}
	response := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	response.Response = true
	c.finishDNSFlight(key, flight, response, nil)
	if c.leaveDNSFlight(key, follower) {
		t.Fatal("timeout won arbitration after flight completion")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	msg := testDNSQuery("ExAmPlE.com.", dnsmessage.TypeA, 2)
	if err := c.waitDNSFlight(ctx, key, follower, msg); err != nil {
		t.Fatal(err)
	}
	if !msg.Response || msg.Id != 2 || msg.Question[0].Name != "ExAmPlE.com." {
		t.Fatalf("completed result lost to timeout: %+v", msg)
	}
}

func TestDNSFlightPanicUnblocksFollower(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	c.dnsDuplicateWaitTimeout = time.Second
	key := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "panic")
	leaderMsg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = c.shareDNSResult(context.Background(), key, leaderMsg, func() error {
			close(started)
			<-release
			leaderMsg.Answer = []dnsmessage.RR{(*dnsmessage.A)(nil)}
			panic("boom")
		})
	}()
	<-started

	followerMsg := testDNSQuery("example.com.", dnsmessage.TypeA, 2)
	followerDone := make(chan error, 1)
	var followerResolved atomic.Bool
	go func() {
		followerDone <- c.shareDNSResult(context.Background(), key, followerMsg, func() error {
			followerResolved.Store(true)
			return nil
		})
	}()
	waitForDnsFlightParticipants(t, c, key, 2)
	close(release)

	if recovered := <-panicked; recovered != "boom" {
		t.Fatalf("leader panic = %v, want boom", recovered)
	}
	if err := <-followerDone; err == nil || err.Error() != "DNS flight panicked: boom" {
		t.Fatalf("follower error = %v", err)
	}
	if followerResolved.Load() {
		t.Fatal("follower unexpectedly became a leader")
	}
	c.dnsFlightMu.Lock()
	remaining := len(c.dnsFlights)
	c.dnsFlightMu.Unlock()
	if remaining != 0 {
		t.Fatalf("panic left %d flights behind", remaining)
	}
}

func TestResponseCacheNormalizesRRSetDeadlines(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	key := dnsCacheKey{queryInfo: queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}}
	short := testARecord("example.com.", "1.1.1.1")
	short.Hdr.Ttl = 30
	long := testARecord("example.com.", "2.2.2.2")
	long.Hdr.Ttl = 120
	start := time.Now()

	cacheTestDNSResponse(c, key, []dnsmessage.RR{short, long})
	caches := getTestDNSCache(c.dnsCache, key)
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
	if d := deadlines["2.2.2.2"].Sub(start); d < 25*time.Second || d > 35*time.Second {
		t.Errorf("one RRset should use its shortest TTL: %v", d)
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

func TestParseFixedDomainTtlRange(t *testing.T) {
	valid := []config.KeyableString{
		"zero.example: 0",
		config.KeyableString("max.example: " + strconv.FormatUint(uint64(math.MaxInt32), 10)),
	}
	if _, err := ParseFixedDomainTtl(valid); err != nil {
		t.Fatalf("valid TTL range rejected: %v", err)
	}
	for _, value := range []config.KeyableString{
		"negative.example: -1",
		config.KeyableString("large.example: " + strconv.FormatUint(uint64(math.MaxInt32)+1, 10)),
	} {
		if _, err := ParseFixedDomainTtl([]config.KeyableString{value}); err == nil {
			t.Fatalf("out-of-range TTL accepted: %v", value)
		}
	}
}

func TestDNSQueryVariantSeparatesResponseVaryingData(t *testing.T) {
	variant := func(t *testing.T, msg *dnsmessage.Msg) string {
		t.Helper()
		got, ok := dnsQueryVariant(msg)
		if !ok {
			t.Fatalf("query was not fingerprintable: %+v", msg)
		}
		return got
	}
	edns := func(size uint16) *dnsmessage.Msg {
		msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
		msg.SetEdns0(size, false)
		return msg
	}
	ecs := func(address string) *dnsmessage.Msg {
		msg := edns(1232)
		msg.IsEdns0().Option = append(msg.IsEdns0().Option, &dnsmessage.EDNS0_SUBNET{
			Code:          dnsmessage.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 24,
			Address:       net.ParseIP(address).To4(),
		})
		return msg
	}
	base := testDNSQuery("EXAMPLE.COM.", dnsmessage.TypeA, 1)
	same := testDNSQuery("example.com.", dnsmessage.TypeA, 65535)
	if variant(t, base) != variant(t, same) {
		t.Fatal("ID and qname case must not split an otherwise identical query")
	}

	tests := []struct {
		name string
		a    *dnsmessage.Msg
		b    *dnsmessage.Msg
	}{
		{
			name: "rd",
			a:    testDNSQuery("example.com.", dnsmessage.TypeA, 1),
			b: func() *dnsmessage.Msg {
				msg := testDNSQuery("example.com.", dnsmessage.TypeA, 2)
				msg.RecursionDesired = false
				return msg
			}(),
		},
		{
			name: "cd",
			a:    testDNSQuery("example.com.", dnsmessage.TypeA, 1),
			b: func() *dnsmessage.Msg {
				msg := testDNSQuery("example.com.", dnsmessage.TypeA, 2)
				msg.CheckingDisabled = true
				return msg
			}(),
		},
		{
			name: "do",
			a:    edns(1232),
			b: func() *dnsmessage.Msg {
				msg := edns(1232)
				msg.IsEdns0().SetDo(true)
				return msg
			}(),
		},
		{name: "udp size", a: edns(1232), b: edns(4096)},
		{
			name: "edns version",
			a:    edns(1232),
			b: func() *dnsmessage.Msg {
				msg := edns(1232)
				msg.IsEdns0().SetVersion(1)
				return msg
			}(),
		},
		{name: "ecs", a: ecs("192.0.2.1"), b: ecs("198.51.100.1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if variant(t, tt.a) == variant(t, tt.b) {
				t.Fatal("response-varying queries produced the same variant")
			}
			if tt.name != "ecs" && tt.name != "udp size" {
				return
			}
			upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "8.8.8.8", Port: 53}
			dialArg := &dialArgument{}
			qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
			queryA, flightA, _ := makeDNSQueryKey(tt.a, qi)
			queryB, flightB, _ := makeDNSQueryKey(tt.b, qi)
			if !flightA || !flightB || queryA == queryB {
				t.Fatalf("flight keys were not separated: a=%+v b=%+v", queryA, queryB)
			}
			forwarderKey := makeDNSForwarderKey(upstream, dialArg)
			keyA := makeDNSCacheKey(queryA, forwarderKey)
			keyB := makeDNSCacheKey(queryB, forwarderKey)
			cache := newCommonDnsCache(2)
			cache.Replace(keyA, []*DnsCache{newDnsCache(testARecord(qi.qname, "1.2.3.4"), time.Now().Add(time.Minute))}, time.Time{})
			if cache.FillInto(keyB, tt.b.Copy()) {
				t.Fatal("one query variant consumed another variant's cache entry")
			}
		})
	}

	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	in := testDNSQuery(qi.qname, qi.qtype, 1)
	chaos := testDNSQuery(qi.qname, qi.qtype, 2)
	chaos.Question[0].Qclass = dnsmessage.ClassCHAOS
	inKey, inFlight, inCache := makeDNSQueryKey(in, qi)
	chaosKey, chaosFlight, chaosCache := makeDNSQueryKey(chaos, qi)
	if !inFlight || !inCache || !chaosFlight || chaosCache || inKey == chaosKey {
		t.Fatalf("QCLASS/reuse policy mismatch: in=%+v chaos=%+v", inKey, chaosKey)
	}
	_, ednsFlight, ednsCache := makeDNSQueryKey(edns(1232), qi)
	if !ednsFlight || ednsCache {
		t.Fatal("EDNS queries should share exact flights but bypass the answer-only cache")
	}

	cookie := edns(1232)
	cookie.IsEdns0().Option = append(cookie.IsEdns0().Option, &dnsmessage.EDNS0_COOKIE{
		Code: dnsmessage.EDNS0COOKIE, Cookie: "0011223344556677",
	})
	if _, ok := dnsQueryVariant(cookie); ok {
		t.Fatal("source-bound cookies must bypass caching and coalescing")
	}

	unsupported := edns(1232)
	unsupported.IsEdns0().Option = append(unsupported.IsEdns0().Option, &dnsmessage.EDNS0_LOCAL{
		Code: dnsmessage.EDNS0LOCALSTART,
		Data: []byte{1},
	})
	if _, ok := dnsQueryVariant(unsupported); ok {
		t.Fatal("unknown EDNS options must bypass caching and coalescing")
	}
	for _, qtype := range []uint16{dnsmessage.TypeAXFR, dnsmessage.TypeIXFR, dnsmessage.TypeTKEY} {
		query := testDNSQuery("example.com.", qtype, 1)
		if _, ok := dnsQueryVariant(query); ok {
			t.Fatalf("stateful or multi-message query type %d must bypass caching and coalescing", qtype)
		}
	}
}

func TestDNSUDPPayloadSizeBounds(t *testing.T) {
	query := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
	if got := dnsUDPPayloadSize(query); got != dnsmessage.MinMsgSize {
		t.Fatalf("plain DNS payload size = %d, want %d", got, dnsmessage.MinMsgSize)
	}
	query.SetEdns0(0, false)
	if got := dnsUDPPayloadSize(query); got != dnsmessage.MinMsgSize {
		t.Fatalf("undersized EDNS payload size = %d, want %d", got, dnsmessage.MinMsgSize)
	}
	query.IsEdns0().SetUDPSize(1232)
	if got := dnsUDPPayloadSize(query); got != 1232 {
		t.Fatalf("EDNS payload size = %d, want 1232", got)
	}
}

func TestCachedFixedTtlResponseKeepsRemainingLifetime(t *testing.T) {
	c, registry, _ := newTestDnsController(t, map[string]int{"pinned.com.": 30})
	qi := queryInfo{qname: "pinned.com.", qtype: dnsmessage.TypeA}
	ip := netip.MustParseAddr("1.1.1.1")

	upstreamResponse := testDNSQuery(qi.qname, qi.qtype, 1)
	upstreamResponse.Response = true
	upstreamResponse.AuthenticatedData = true
	upstreamResponse.Answer = []dnsmessage.RR{testARecord("pinned.com.", ip.String())}
	upstreamResponse.Answer[0].Header().Ttl = 3600
	c.finalizeAcceptedResponse(upstreamResponse, &pendingDNSResponse{
		cacheKey: testDNSCacheKey(qi), register: true,
		receivedAt: time.Now(),
	})
	registration := registry.byName[qi][ip]
	if registration == nil {
		t.Fatal("upstream response should register its address")
	}
	registryDeadline := registration.effectiveExpiry()
	if got := upstreamResponse.Answer[0].Header().Ttl; got != 30 {
		t.Fatalf("fresh upstream response should apply fixed TTL: %v", got)
	}
	if upstreamResponse.AuthenticatedData {
		t.Fatal("fresh forwarded response must not assert validation dae did not perform")
	}

	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "8.8.8.8", Port: 53}
	dialArg := &dialArgument{}
	forwarderKey := makeDNSForwarderKey(upstream, dialArg)
	cachedResponse := testDNSQuery(qi.qname, qi.qtype, 7)
	queryKey, _, cacheable := makeDNSQueryKey(cachedResponse, qi)
	cacheKey := makeDNSCacheKey(queryKey, forwarderKey)
	if !cacheable {
		t.Fatal("plain IN query should be cacheable")
	}
	c.dnsForwarderCache[forwarderKey] = failDnsForwarder{t: t}
	c.dnsCache.Replace(cacheKey, []*DnsCache{
		newDnsCache(upstreamResponse.Answer[0], time.Now().Add(5*time.Second)),
	}, time.Time{})
	pending, err := c.dialSend(context.Background(), cachedResponse, upstream, dialArg, queryKey, cacheable, true)
	if err != nil {
		t.Fatal(err)
	}
	if pending != nil {
		t.Fatal("cache hit should have no pending upstream work")
	}
	if len(cachedResponse.Answer) != 1 {
		t.Fatalf("expected one cached answer: %v", cachedResponse.Answer)
	}
	remainingTTL := cachedResponse.Answer[0].Header().Ttl
	if remainingTTL == 0 || remainingTTL > 5 {
		t.Fatalf("cached response should expose its remaining TTL: %v", remainingTTL)
	}

	c.finalizeAcceptedResponse(cachedResponse, pending)
	if got := cachedResponse.Answer[0].Header().Ttl; got != remainingTTL {
		t.Fatalf("fixed TTL must not restart on a cache hit: got %v, want %v", got, remainingTTL)
	}
	if got := registry.byName[qi][ip].effectiveExpiry(); !got.Equal(registryDeadline) {
		t.Fatalf("cache hit must not refresh the registry: got %v, want %v", got, registryDeadline)
	}
}

func TestValidateDNSResponseIdentity(t *testing.T) {
	request := testDNSQuery("example.com.", dnsmessage.TypeA, 42)
	valid := request.Copy()
	valid.Response = true
	valid.Question[0].Name = "EXAMPLE.COM."
	if err := validateDNSResponseIdentity(request, valid); err != nil {
		t.Fatalf("case-insensitive matching response was rejected: %v", err)
	}

	tests := map[string]func(*dnsmessage.Msg){
		"request bit": func(msg *dnsmessage.Msg) { msg.Response = false },
		"id":          func(msg *dnsmessage.Msg) { msg.Id++ },
		"opcode":      func(msg *dnsmessage.Msg) { msg.Opcode++ },
		"qname":       func(msg *dnsmessage.Msg) { msg.Question[0].Name = "other.example." },
		"qtype":       func(msg *dnsmessage.Msg) { msg.Question[0].Qtype = dnsmessage.TypeAAAA },
		"qclass":      func(msg *dnsmessage.Msg) { msg.Question[0].Qclass = dnsmessage.ClassCHAOS },
		"no question": func(msg *dnsmessage.Msg) { msg.Question = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := valid.Copy()
			mutate(response)
			if err := validateDNSResponseIdentity(request, response); err == nil {
				t.Fatal("mismatched response was accepted")
			}
		})
	}
}

func TestFinalizeUsesUpstreamReceiveTimeForTTL(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	receivedAt := time.Now().Add(-5 * time.Second)
	response := testDNSQuery(qi.qname, qi.qtype, 1)
	response.Response = true
	answer := testARecord(qi.qname, "1.2.3.4")
	answer.Hdr.Ttl = 10
	response.Answer = []dnsmessage.RR{answer}
	c.finalizeAcceptedResponse(response, &pendingDNSResponse{
		cacheKey: testDNSCacheKey(qi), register: true,
		receivedAt: receivedAt,
	})

	ip := netip.MustParseAddr("1.2.3.4")
	if got := registry.byName[qi][ip].effectiveExpiry(); !got.Equal(receivedAt.Add(10 * time.Second)) {
		t.Fatalf("registry TTL started after response routing: %v", got)
	}
	if got := response.Answer[0].Header().Ttl; got < 4 || got > 5 {
		t.Fatalf("wire TTL did not account for response-routing delay: %v", got)
	}
}

func TestDNSFlightFansOutNonCacheableResponse(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	key := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "non-cacheable-flight")
	leaderMsg := testDNSQuery("EXAMPLE.COM.", dnsmessage.TypeA, 1)
	followerMsg := testDNSQuery("example.com.", dnsmessage.TypeA, 2)
	leaderStarted := make(chan struct{})
	releaseLeader := make(chan struct{})
	var calls atomic.Int32

	leaderDone := make(chan error, 1)
	go func() {
		leaderDone <- c.shareDNSResult(context.Background(), key, leaderMsg, func() error {
			calls.Add(1)
			close(leaderStarted)
			<-releaseLeader
			leaderMsg.Response = true
			leaderMsg.Rcode = dnsmessage.RcodeSuccess
			leaderMsg.Truncated = true
			leaderMsg.Answer = []dnsmessage.RR{testARecord("example.com.", "1.2.3.4")}
			return nil
		})
	}()
	<-leaderStarted

	c.dnsFlightMu.Lock()
	flight := c.dnsFlights[key]
	c.dnsFlightMu.Unlock()
	if flight == nil {
		t.Fatal("leader did not publish its flight")
	}
	followerFlight, followerIsLeader, err := c.joinDNSFlight(key)
	if err != nil {
		t.Fatal(err)
	}
	if followerIsLeader || followerFlight != flight {
		t.Fatal("follower did not join the existing flight")
	}
	followerDone := make(chan error, 1)
	go func() { followerDone <- c.waitDNSFlight(context.Background(), key, followerFlight, followerMsg) }()
	close(releaseLeader)

	if err := <-leaderDone; err != nil {
		t.Fatalf("leader failed: %v", err)
	}
	if err := <-followerDone; err != nil {
		t.Fatalf("follower failed: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("one flight performed %v resolutions", calls.Load())
	}
	if !leaderMsg.Truncated || !followerMsg.Truncated || len(followerMsg.Answer) != 1 {
		t.Fatalf("non-cacheable response was not fanned out: %+v", followerMsg)
	}
	if followerMsg.Id != 2 || !reflect.DeepEqual(followerMsg.Question, testDNSQuery("example.com.", dnsmessage.TypeA, 2).Question) {
		t.Fatalf("follower transaction identity was not preserved: %+v", followerMsg.Question)
	}
	followerMsg.Answer[0].(*dnsmessage.A).A[0] = 9
	if leaderMsg.Answer[0].(*dnsmessage.A).A[0] == 9 {
		t.Fatal("flight followers must receive independent deep copies")
	}
}

func TestDNSFlightKeyIncludesRerouteContext(t *testing.T) {
	first := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "")
	first.route.src = netip.MustParseAddrPort("192.0.2.1:1000")
	second := first
	second.route.src = netip.MustParseAddrPort("192.0.2.2:1000")
	if first == second {
		t.Fatal("source-dependent reroute contexts shared one flight key")
	}
	second = first
	second.route.pname[0] = 1
	if first == second {
		t.Fatal("process-dependent reroute contexts shared one flight key")
	}
}

func TestDNSFlightCloseUnblocksWaiter(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	key := testDNSFlightKey(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, "close-flight")
	leaderStarted := make(chan struct{})
	leaderDone := make(chan error, 1)
	go func() {
		msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
		leaderDone <- c.shareDNSResult(context.Background(), key, msg, func() error {
			close(leaderStarted)
			<-c.closed.Done()
			return net.ErrClosed
		})
	}()
	<-leaderStarted

	c.dnsFlightMu.Lock()
	flight := c.dnsFlights[key]
	c.dnsFlightMu.Unlock()
	followerFlight, followerIsLeader, err := c.joinDNSFlight(key)
	if err != nil {
		t.Fatal(err)
	}
	if followerIsLeader || followerFlight != flight {
		t.Fatal("follower did not join the existing flight")
	}
	followerDone := make(chan error, 1)
	go func() {
		msg := testDNSQuery("example.com.", dnsmessage.TypeA, 2)
		followerDone <- c.waitDNSFlight(context.Background(), key, followerFlight, msg)
	}()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-leaderDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("leader close result: %v", err)
	}
	if err := <-followerDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("follower close result: %v", err)
	}
}

func TestDnsControllerCloseInterruptsForwarderAndPreventsReuse(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "8.8.8.8", Port: 53}
	dialArg := &dialArgument{}
	forwarder := &blockingDnsForwarder{started: make(chan struct{}), closed: make(chan struct{})}
	forwarderKey := makeDNSForwarderKey(upstream, dialArg)
	c.dnsForwarderCache[forwarderKey] = forwarder
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}

	if !c.admitDNSRequest() {
		t.Fatal("open controller rejected request admission")
	}
	requestDone := make(chan error, 1)
	go func() {
		defer c.activeRequests.Done()
		query := testDNSQuery(qi.qname, qi.qtype, 1)
		queryKey, _, cacheable := makeDNSQueryKey(query, qi)
		_, err := c.dialSend(context.Background(), query, upstream, dialArg, queryKey, cacheable, true)
		requestDone <- err
	}()
	<-forwarder.started
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-requestDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("active request was not interrupted: %v", err)
	}
	query := testDNSQuery(qi.qname, qi.qtype, 2)
	queryKey, _, cacheable := makeDNSQueryKey(query, qi)
	if _, err := c.dialSend(context.Background(), query, upstream, dialArg, queryKey, cacheable, true); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("request after Close did not fail closed: %v", err)
	}
	if forwarder.calls.Load() != 1 || forwarder.closes.Load() != 1 {
		t.Fatalf("forwarder lifecycle: calls=%v closes=%v", forwarder.calls.Load(), forwarder.closes.Load())
	}
}

func TestDnsControllerCloseWaitsForAdmittedRequestSend(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	c.sendPacket = func([]byte, netip.AddrPort, netip.AddrPort) error {
		close(started)
		<-release
		return nil
	}
	sendDone := make(chan error, 1)
	if !c.admitDNSRequest() {
		t.Fatal("open controller rejected request admission")
	}
	go func() {
		defer c.activeRequests.Done()
		sendDone <- c.sendDNSPacket(nil, netip.AddrPort{}, netip.AddrPort{})
	}()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()

	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before the admitted send finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := c.sendDNSPacket(nil, netip.AddrPort{}, netip.AddrPort{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after Close did not fail closed: %v", err)
	}
}

func TestDnsControllerCloseWaitsForAdmittedRequest(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	if !c.admitDNSRequest() {
		t.Fatal("open controller rejected request admission")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before admitted request finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	c.activeRequests.Done()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if c.admitDNSRequest() {
		c.activeRequests.Done()
		t.Fatal("closed controller admitted a request")
	}
}

func TestRegisterAnswersNoExpiryIgnoresFixedTtl(t *testing.T) {
	c, registry, fake := newTestDnsController(t, map[string]int{"resolver.example.": 0})
	qi := queryInfo{qname: "resolver.example.", qtype: dnsmessage.TypeA}
	ip := netip.MustParseAddr("1.1.1.1")
	c.registerAddressNoExpiry(qi, ip)

	registration := registry.byName[qi][ip]
	if registration == nil || !fake.has(ip) {
		t.Fatal("synthetic upstream address should be registered in the kernel maps")
	}
	if !registration.effectiveExpiry().IsZero() {
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
	c.registerAddressNoExpiry(qi, netip.MustParseAddr("1.1.1.1"))
	if registry.Size() != 0 {
		t.Fatal("synthetic registration mutated the registry after Close")
	}
}

func TestRegisterResponsePlanAfterCloseIsNoop(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	registerTestDNSResponse(c, queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA},
		[]dnsmessage.RR{testARecord("example.com.", "1.2.3.4")})
	if registry.Size() != 0 {
		t.Fatal("response plan mutated the registry after Close")
	}
}

func TestAcceptedResponseDuringCloseDoesNotPublish(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	if !c.admitDNSRequest() {
		t.Fatal("open controller rejected request admission")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	for c.closed.Err() == nil {
		time.Sleep(time.Millisecond)
	}

	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	msg := testDNSQuery(qi.qname, qi.qtype, 1)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{testARecord(qi.qname, "1.2.3.4")}
	c.finalizeAcceptedResponse(msg, &pendingDNSResponse{
		cacheKey: testDNSCacheKey(qi), register: true, receivedAt: time.Now(),
	})
	c.activeRequests.Done()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if registry.Size() != 0 {
		t.Fatal("retiring controller published an accepted response")
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
	msg := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
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
	c.dnsForwarderCache[dnsForwarderKey{}] = forwarder
	if !c.admitDNSRequest() {
		t.Fatal("open controller rejected request registration")
	}
	requestDone := false
	defer func() {
		if !requestDone {
			c.activeRequests.Done()
		}
	}()

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
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt forwarders while draining requests")
	}
	select {
	case err := <-done:
		t.Fatalf("Close returned before the admitted request ended: %v", err)
	default:
	}

	c.activeRequests.Done()
	requestDone = true
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after the request ended")
	}
	if c.admitDNSRequest() {
		c.activeRequests.Done()
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
	key := makeDNSForwarderKey(upstream, dialArg)
	forwarder := &cancelAwareDnsForwarder{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	c.dnsForwarderCache[key] = forwarder
	if !c.admitDNSRequest() {
		t.Fatal("open controller rejected request registration")
	}
	requestDone := make(chan error, 1)
	go func() {
		defer c.activeRequests.Done()
		qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
		query := testDNSQuery(qi.qname, qi.qtype, 1)
		queryKey, _, cacheable := makeDNSQueryKey(query, qi)
		_, err := c.dialSend(c.closed, query, upstream, dialArg, queryKey, cacheable, true)
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
