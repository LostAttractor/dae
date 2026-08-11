/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"net/netip"
	"strconv"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func TestResponsePlanCachesAndRegistersCNAMEViews(t *testing.T) {
	registry, fake := newTestRegistry(16, 16, 10*time.Second)
	c, err := NewDnsController(nil, &DnsControllerOption{
		MatchBitmap: func(fqdn string) []uint32 {
			switch fqdn {
			case "www.example.":
				return testBitmap(1)
			case "edge.cdn.example.":
				return testBitmap(2)
			default:
				return testBitmap()
			}
		},
		DomainRegistry: registry,
	})
	if err != nil {
		t.Fatal(err)
	}

	cname := testCNAMERecord("WWW.Example.", "EDGE.CDN.Example.")
	cname.Hdr.Ttl = 60
	address := testARecord("edge.cdn.example.", "1.2.3.4")
	address.Hdr.Ttl = 3600
	answers := []dnsmessage.RR{cname, address}
	now := time.Now()
	plan := c.planDNSResponse(queryInfo{qname: "WWW.Example", qtype: dnsmessage.TypeA}, answers)
	if plan == nil || len(plan.views) != 2 {
		t.Fatalf("expected alias and terminal views: %+v", plan)
	}
	alias, terminal := plan.views[0], plan.views[1]
	if alias.query.qname != "www.example." || len(alias.answers) != 2 || len(alias.addresses) != 1 {
		t.Fatalf("unexpected alias view: %+v", alias)
	}
	if alias.unitTTLSeconds != 60 || !alias.expiresAsUnit {
		t.Fatalf("alias cache should expire as one 60s chain: %+v", alias)
	}
	if alias.answers[0].ttlSeconds != 60 || alias.answers[1].ttlSeconds != 3600 {
		t.Fatalf("wire TTLs should remain RRset-specific: %+v", alias.answers)
	}
	if terminal.query.qname != "edge.cdn.example." || len(terminal.answers) != 1 || terminal.answers[0].ttlSeconds != 3600 {
		t.Fatalf("terminal view should preserve its RRset TTL: %+v", terminal)
	}

	baseKey := dnsCacheKey{
		queryInfo:       alias.query,
		dnsForwarderKey: dnsForwarderKey{upstream: "resolver-one"},
		qclass:          dnsmessage.ClassINET,
	}
	targetKey := baseKey
	targetKey.queryInfo = terminal.query
	if cached := c.dnsCache.Get(baseKey); cached != nil {
		t.Fatalf("cache must not be visible before response acceptance: %+v", cached)
	}

	msg := &dnsmessage.Msg{Answer: answers}
	c.commitAcceptedResponse(msg, &pendingDNSResponse{
		cacheKey: baseKey,
	}, now)
	if msg.Answer[0].Header().Ttl != 60 || msg.Answer[1].Header().Ttl != 3600 {
		t.Fatalf("client response should preserve RRset TTLs: %+v", msg.Answer)
	}
	aliasCache := c.dnsCache.Get(baseKey)
	targetCache := c.dnsCache.Get(targetKey)
	if len(aliasCache) != 2 || len(targetCache) != 1 {
		t.Fatalf("accepted response did not publish all cache views: alias=%+v target=%+v", aliasCache, targetCache)
	}
	if !aliasCache[0].Deadline.Equal(now.Add(60*time.Second)) || !aliasCache[1].Deadline.Equal(now.Add(3600*time.Second)) {
		t.Fatalf("alias cache should preserve wire deadlines: %+v", aliasCache)
	}
	entry := c.dnsCache.cache[baseKey].Value.(*cacheEntry[dnsCacheKey])
	if !entry.validUntil.Equal(now.Add(60 * time.Second)) {
		t.Fatalf("alias dependency deadline: got %v", entry.validUntil)
	}
	if want := now.Add(3600 * time.Second); !targetCache[0].Deadline.Equal(want) {
		t.Fatalf("terminal cache deadline: got %v, want %v", targetCache[0].Deadline, want)
	}
	otherUpstreamKey := targetKey
	otherUpstreamKey.upstream = "resolver-two"
	if cached := c.dnsCache.Get(otherUpstreamKey); cached != nil {
		t.Fatalf("derived cache leaked across upstreams: %+v", cached)
	}
	ip := netip.MustParseAddr("1.2.3.4")
	aliasRegistration := registry.byName[alias.query][ip]
	targetRegistration := registry.byName[terminal.query][ip]
	if aliasRegistration == nil || targetRegistration == nil {
		t.Fatalf("both names should be registered: alias=%+v target=%+v", aliasRegistration, targetRegistration)
	}
	if !aliasRegistration.expiry.Equal(now.Add(60 * time.Second)) {
		t.Fatalf("alias registration expiry: %v", aliasRegistration.expiry)
	}
	if !targetRegistration.expiry.Equal(now.Add(3600 * time.Second)) {
		t.Fatalf("target registration expiry: %v", targetRegistration.expiry)
	}
	if !bitmapHas(fake.bump[ip], 1) || !bitmapHas(fake.bump[ip], 2) {
		t.Fatalf("kernel bump bitmap should include both names: %v", fake.bump[ip])
	}
	if bitmapHas(fake.routing[ip], 1) || bitmapHas(fake.routing[ip], 2) {
		t.Fatalf("different name rules should make the IP ambiguous: %v", fake.routing[ip])
	}
	checkInvariants(t, registry, fake)
}

func TestResponsePlanDoesNotCacheIncompleteDNSSECResponse(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA}
	now := time.Now().Truncate(time.Second)
	cname := testCNAMERecord(qi.qname, "edge.example.")
	address := testARecord("edge.example.", "1.2.3.4")
	signature := &dnsmessage.RRSIG{
		Hdr: dnsmessage.RR_Header{
			Name:   "edge.example.",
			Rrtype: dnsmessage.TypeRRSIG,
			Class:  dnsmessage.ClassINET,
			Ttl:    30,
		},
		TypeCovered: dnsmessage.TypeA,
		Algorithm:   8,
		Labels:      2,
		OrigTtl:     60,
		Inception:   uint32(now.Add(-time.Minute).Unix()),
		Expiration:  uint32(now.Add(30 * time.Second).Unix()),
		SignerName:  "example.",
		Signature:   "AA==",
	}
	answers := []dnsmessage.RR{cname, address, signature}
	plan := c.planDNSResponseAt(qi, answers, now)
	if plan == nil || !plan.signed || plan.publishDerivedCache {
		t.Fatalf("DNSSEC response should suppress derived cache publication: %+v", plan)
	}
	if got := plan.views[0].unitTTLSeconds; got != 30 {
		t.Fatalf("signature expiration should cap the response at 30s: %v", got)
	}
	baseKey := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	c.commitAcceptedResponse(&dnsmessage.Msg{Answer: answers}, &pendingDNSResponse{cacheKey: baseKey}, now)
	targetKey := baseKey
	targetKey.queryInfo.qname = "edge.example."
	if cached := c.dnsCache.Get(targetKey); cached != nil {
		t.Fatalf("derived DNSSEC cache omitted signatures: %+v", cached)
	}
	if cached := c.dnsCache.Get(baseKey); cached != nil {
		t.Fatalf("answer-only cache must not retain signed responses: %+v", cached)
	}
	ip := netip.MustParseAddr("1.2.3.4")
	registration := registry.byName[targetKey.queryInfo][ip]
	if registration == nil || !registration.expiry.Equal(now.Add(30*time.Second)) {
		t.Fatal("accepted DNSSEC response should still register the terminal DNS evidence")
	}
}

func TestResponsePlanFixedTTLCannotExtendRRSIG(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	c, registry, _ := newTestDnsController(t, map[string]int{"signed.example.": 300})
	qi := queryInfo{qname: "signed.example.", qtype: dnsmessage.TypeA}
	address := testARecord(qi.qname, "1.2.3.4")
	address.Hdr.Ttl = 120
	signature := &dnsmessage.RRSIG{
		Hdr: dnsmessage.RR_Header{
			Name: qi.qname, Rrtype: dnsmessage.TypeRRSIG,
			Class: dnsmessage.ClassINET, Ttl: 90,
		},
		TypeCovered: dnsmessage.TypeA,
		Algorithm:   8,
		Labels:      2,
		OrigTtl:     60,
		Inception:   uint32(now.Add(-time.Minute).Unix()),
		Expiration:  uint32(now.Add(20 * time.Second).Unix()),
		SignerName:  "example.",
		Signature:   "AA==",
	}
	answers := []dnsmessage.RR{address, signature}
	plan := c.planDNSResponseAt(qi, answers, now)
	if plan == nil || !plan.signed || len(plan.views[0].addresses) != 1 || plan.views[0].addresses[0].ttlSeconds != 20 {
		t.Fatalf("signed plan was not capped by signature validity: %+v", plan)
	}
	for _, answer := range plan.views[0].answers {
		if answer.ttlSeconds != 20 {
			t.Fatalf("fixed TTL extended signed data: %+v", plan.views[0].answers)
		}
	}

	key := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	msg := &dnsmessage.Msg{Answer: answers}
	c.commitAcceptedResponse(msg, &pendingDNSResponse{cacheKey: key}, now)
	if cached := c.dnsCache.Get(key); cached != nil {
		t.Fatalf("signed answer entered the answer-only cache: %+v", cached)
	}
	ip := netip.MustParseAddr("1.2.3.4")
	if got := registry.byName[qi][ip].expiry; !got.Equal(now.Add(20 * time.Second)) {
		t.Fatalf("signed registry lease exceeded signature validity: %v", got)
	}
	for _, answer := range msg.Answer {
		if answer.Header().Ttl != 20 {
			t.Fatalf("wire TTL exceeded signature validity: %+v", msg.Answer)
		}
	}
}

func TestResponsePlanRRSIGBoundsOnlyCoveredRRSet(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	c, _, _ := newTestDnsController(t, map[string]int{"signed.example.": 300})
	qi := queryInfo{qname: "signed.example.", qtype: dnsmessage.TypeA}
	address := testARecord(qi.qname, "1.2.3.4")
	address.Hdr.Ttl = 120
	aSignature := &dnsmessage.RRSIG{
		Hdr:         dnsmessage.RR_Header{Name: qi.qname, Rrtype: dnsmessage.TypeRRSIG, Class: dnsmessage.ClassINET, Ttl: 90},
		TypeCovered: dnsmessage.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 60,
		Inception: uint32(now.Add(-time.Minute).Unix()), Expiration: uint32(now.Add(20 * time.Second).Unix()),
		SignerName: "example.", Signature: "AA==",
	}
	orphanSignature := &dnsmessage.RRSIG{
		Hdr:         dnsmessage.RR_Header{Name: qi.qname, Rrtype: dnsmessage.TypeRRSIG, Class: dnsmessage.ClassINET, Ttl: 1},
		TypeCovered: dnsmessage.TypeTXT, Algorithm: 8, Labels: 2, OrigTtl: 1,
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(-time.Minute).Unix()),
		SignerName: "example.", Signature: "AA==",
	}
	plan := c.planDNSResponseAt(qi, []dnsmessage.RR{address, aSignature, orphanSignature}, now)
	if plan == nil || len(plan.views) != 1 || len(plan.views[0].addresses) != 1 {
		t.Fatalf("unexpected signed plan: %+v", plan)
	}
	if got := plan.views[0].addresses[0].ttlSeconds; got != 20 {
		t.Fatalf("orphan RRSIG changed the A RRset bound: %v", got)
	}
	var signatureTTLs = make(map[uint16]int)
	for _, answer := range plan.views[0].answers {
		if signature, ok := answer.answer.(*dnsmessage.RRSIG); ok {
			signatureTTLs[signature.TypeCovered] = answer.ttlSeconds
		}
	}
	if signatureTTLs[dnsmessage.TypeA] != 20 || signatureTTLs[dnsmessage.TypeTXT] != 0 {
		t.Fatalf("RRSIGs for different covered types were conflated: %v", signatureTTLs)
	}
}

func TestResponsePlanUsesLongestUsableRRSIGAlternative(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	c, _, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "signed.example.", qtype: dnsmessage.TypeA}
	address := testARecord(qi.qname, "1.2.3.4")
	address.Hdr.Ttl = 120
	newSignature := func(expiration time.Time, ttl uint32) *dnsmessage.RRSIG {
		return &dnsmessage.RRSIG{
			Hdr:         dnsmessage.RR_Header{Name: qi.qname, Rrtype: dnsmessage.TypeRRSIG, Class: dnsmessage.ClassINET, Ttl: ttl},
			TypeCovered: dnsmessage.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 120,
			Inception: uint32(now.Add(-time.Minute).Unix()), Expiration: uint32(expiration.Unix()),
			SignerName: "example.", Signature: "AA==",
		}
	}
	answers := []dnsmessage.RR{
		address,
		newSignature(now.Add(20*time.Second), 20),
		newSignature(now.Add(80*time.Second), 120),
		newSignature(now.Add(-time.Second), 1),
	}
	plan := c.planDNSResponseAt(qi, answers, now)
	if plan == nil || len(plan.views) != 1 || len(plan.views[0].addresses) != 1 {
		t.Fatalf("unexpected signed plan: %+v", plan)
	}
	if got := plan.views[0].addresses[0].ttlSeconds; got != 80 {
		t.Fatalf("covered RRset used the shortest signature instead of the longest usable alternative: %v", got)
	}
	wantSignatureTTLs := map[uint32]int{
		uint32(now.Add(20 * time.Second).Unix()): 20,
		uint32(now.Add(80 * time.Second).Unix()): 80,
		uint32(now.Add(-time.Second).Unix()):     0,
	}
	for _, answer := range plan.views[0].answers {
		signature, ok := answer.answer.(*dnsmessage.RRSIG)
		if !ok {
			continue
		}
		if want := wantSignatureTTLs[signature.Expiration]; answer.ttlSeconds != want {
			t.Errorf("signature %v TTL: got %v, want %v", signature.Expiration, answer.ttlSeconds, want)
		}
	}
}

func TestSignedCNAMEDoesNotMakeTerminalAddressSigned(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newAnswers := func(addressTTL uint32) []dnsmessage.RR {
		cname := testCNAMERecord("www.example.", "edge.example.")
		cname.Hdr.Ttl = 120
		address := testARecord("edge.example.", "1.2.3.4")
		address.Hdr.Ttl = addressTTL
		signature := &dnsmessage.RRSIG{
			Hdr:         dnsmessage.RR_Header{Name: "www.example.", Rrtype: dnsmessage.TypeRRSIG, Class: dnsmessage.ClassINET, Ttl: 120},
			TypeCovered: dnsmessage.TypeCNAME, Algorithm: 8, Labels: 2, OrigTtl: 120,
			Inception: uint32(now.Add(-time.Minute).Unix()), Expiration: uint32(now.Add(20 * time.Second).Unix()),
			SignerName: "example.", Signature: "AA==",
		}
		return []dnsmessage.RR{cname, address, signature}
	}
	qi := queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA}
	ip := netip.MustParseAddr("1.2.3.4")

	t.Run("fixed ttl", func(t *testing.T) {
		c, registry, _ := newTestDnsController(t, map[string]int{"edge.example.": 30})
		plan := c.planDNSResponseAt(qi, newAnswers(100), now)
		if plan == nil || len(plan.views) != 2 || plan.views[1].addresses[0].exactDeadline {
			t.Fatalf("terminal address inherited CNAME signedness: %+v", plan)
		}
		if got := plan.views[1].addresses[0].ttlSeconds; got != 30 {
			t.Fatalf("unsigned terminal did not retain fixed TTL: %v", got)
		}
		c.registerResponsePlan(plan, now)
		terminalQI := queryInfo{qname: "edge.example.", qtype: dnsmessage.TypeA}
		if got := registry.byName[terminalQI][ip].expiry; !got.Equal(now.Add(30 * time.Second)) {
			t.Fatalf("terminal registration deadline: %v", got)
		}
	})

	t.Run("registry floor", func(t *testing.T) {
		c, registry, _ := newTestDnsController(t, nil)
		plan := c.planDNSResponseAt(qi, newAnswers(1), now)
		c.registerResponsePlan(plan, now)
		terminalQI := queryInfo{qname: "edge.example.", qtype: dnsmessage.TypeA}
		if got := registry.byName[terminalQI][ip].expiry; !got.Equal(now.Add(10 * time.Second)) {
			t.Fatalf("unsigned terminal lost the ordinary registry floor: %v", got)
		}
	})
}

func TestRRSIGRemainingTTLHandlesSerialRollover(t *testing.T) {
	nowSerial := uint32(math.MaxUint32 - 5)
	signature := &dnsmessage.RRSIG{
		Inception:  math.MaxUint32 - 15,
		Expiration: 4,
	}
	got, valid := rrsigRemainingTTL(signature, time.Unix(int64(nowSerial), 0))
	if !valid || got != 10 {
		t.Fatalf("wrapped validity interval: ttl=%v valid=%v", got, valid)
	}
}

func TestSignedRegistryDeadlineBypassesMinTTL(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	registry, fake := newTestRegistry(16, 16, 7*24*time.Hour)
	c, err := NewDnsController(nil, &DnsControllerOption{
		MatchBitmap:    func(string) []uint32 { return testBitmap(0) },
		DomainRegistry: registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	qi := queryInfo{qname: "signed.example.", qtype: dnsmessage.TypeA}
	address := testARecord(qi.qname, "1.2.3.4")
	signature := &dnsmessage.RRSIG{
		Hdr:         dnsmessage.RR_Header{Name: qi.qname, Rrtype: dnsmessage.TypeRRSIG, Class: dnsmessage.ClassINET, Ttl: 60},
		TypeCovered: dnsmessage.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 60,
		Inception: uint32(now.Add(-time.Minute).Unix()), Expiration: uint32(now.Add(30 * time.Second).Unix()),
		SignerName: "example.", Signature: "AA==",
	}
	key := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	c.commitAcceptedResponse(&dnsmessage.Msg{Answer: []dnsmessage.RR{address, signature}}, &pendingDNSResponse{cacheKey: key}, now)
	ip := netip.MustParseAddr("1.2.3.4")
	registration := registry.byName[qi][ip]
	if registration == nil || !registration.expiry.Equal(now.Add(30*time.Second)) || !fake.has(ip) {
		t.Fatalf("signed evidence did not keep its exact deadline: %+v", registration)
	}
}

func TestResponsePlanDoesNotCacheCNAMENODATA(t *testing.T) {
	c, registry, _ := newTestDnsController(t, map[string]int{"www.example.": 15})
	qi := queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA}
	cname := testCNAMERecord(qi.qname, "missing.example.")
	soa := &dnsmessage.SOA{
		Hdr: dnsmessage.RR_Header{
			Name: "example.", Rrtype: dnsmessage.TypeSOA,
			Class: dnsmessage.ClassINET, Ttl: 30,
		},
		Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 10,
	}
	key := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	msg := &dnsmessage.Msg{Answer: []dnsmessage.RR{cname}, Ns: []dnsmessage.RR{soa}}
	c.commitAcceptedResponse(msg, &pendingDNSResponse{cacheKey: key}, time.Now())
	if cached := c.dnsCache.Get(key); cached != nil {
		t.Fatalf("CNAME NODATA lost its Authority section in cache: %+v", cached)
	}
	if registry.Size() != 0 {
		t.Fatalf("CNAME NODATA created address evidence: %v", registry.Size())
	}
	if got := msg.Answer[0].Header().Ttl; got != 15 {
		t.Fatalf("CNAME NODATA skipped wire TTL policy: %v", got)
	}
}

func TestResponsePlanRejectsMixedAnswerClasses(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	in := testARecord(qi.qname, "1.2.3.4")
	chaos := testARecord(qi.qname, "5.6.7.8")
	chaos.Hdr.Class = dnsmessage.ClassCHAOS
	if plan := c.planDNSResponse(qi, []dnsmessage.RR{in, chaos}); plan != nil {
		t.Fatalf("mixed-class response must bypass answer-only planning: %+v", plan)
	}
	key := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	c.commitAcceptedResponse(&dnsmessage.Msg{Answer: []dnsmessage.RR{in, chaos}}, &pendingDNSResponse{cacheKey: key}, time.Now())
	if c.dnsCache.Get(key) != nil || registry.Size() != 0 {
		t.Fatal("mixed-class response produced cache or routing evidence")
	}
}

func TestCommitRejectsReservedQClass(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	key := dnsCacheKey{queryInfo: qi, qclass: 0}
	c.commitAcceptedResponse(
		&dnsmessage.Msg{Answer: []dnsmessage.RR{testARecord(qi.qname, "1.2.3.4")}},
		&pendingDNSResponse{cacheKey: key}, time.Now(),
	)
	if c.dnsCache.Get(key) != nil || registry.Size() != 0 {
		t.Fatal("reserved QCLASS produced cache or routing evidence")
	}
}

func TestCNAMECacheExpiresRootAsUnit(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA}
	cname := testCNAMERecord(qi.qname, "edge.example.")
	cname.Hdr.Ttl = 60
	address := testARecord("edge.example.", "1.2.3.4")
	address.Hdr.Ttl = 3600
	plan := c.planDNSResponse(qi, []dnsmessage.RR{cname, address})
	baseKey := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	c.cacheResponsePlan(baseKey, plan, time.Now().Add(-61*time.Second))
	if cached := c.dnsCache.Get(baseKey); cached != nil {
		t.Fatalf("expired CNAME dependency left a partial root response: %+v", cached)
	}
	targetKey := baseKey
	targetKey.queryInfo.qname = "edge.example."
	if cached := c.dnsCache.Get(targetKey); len(cached) != 1 {
		t.Fatalf("terminal RRset should retain its independent lifetime: %+v", cached)
	}
}

func TestDirectCacheExpiresWithRequestedRRSet(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	address := testARecord(qi.qname, "1.2.3.4")
	address.Hdr.Ttl = 1
	unrelated := &dnsmessage.TXT{
		Hdr: dnsmessage.RR_Header{Name: "other.example.", Rrtype: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, Ttl: 300},
		Txt: []string{"still live"},
	}
	plan := c.planDNSResponse(qi, []dnsmessage.RR{address, unrelated})
	key := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	c.cacheResponsePlan(key, plan, time.Now().Add(-2*time.Second))
	if cached := c.dnsCache.Get(key); cached != nil {
		t.Fatalf("unrelated Answer data kept an expired requested RRset cacheable: %+v", cached)
	}
}

func TestDirectResponseWithoutRequestedRRSetBypassesCache(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	unrelated := &dnsmessage.TXT{
		Hdr: dnsmessage.RR_Header{Name: "other.example.", Rrtype: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, Ttl: 300},
		Txt: []string{"unrelated"},
	}
	plan := c.planDNSResponse(qi, []dnsmessage.RR{unrelated})
	if plan == nil || !plan.suppressCache {
		t.Fatalf("response without the requested RRset should bypass answer-only cache: %+v", plan)
	}
	key := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	c.cacheResponsePlan(key, plan, time.Now())
	if cached := c.dnsCache.Get(key); cached != nil || registry.Size() != 0 {
		t.Fatalf("unrelated response created state: cache=%+v registry=%v", cached, registry.Size())
	}
}

func TestDisconnectedCNAMEWithoutRequestedRRSetBypassesCache(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeTXT}
	cname := testCNAMERecord("other.example.", "target.example.")
	txt := &dnsmessage.TXT{
		Hdr: dnsmessage.RR_Header{Name: "target.example.", Rrtype: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, Ttl: 300},
		Txt: []string{"unrelated"},
	}
	plan := c.planDNSResponse(qi, []dnsmessage.RR{cname, txt})
	if plan == nil || !plan.suppressCache {
		t.Fatalf("disconnected CNAME response without the requested RRset should bypass cache: %+v", plan)
	}
}

func TestDelayedSignedResponseCannotRegisterExpiredEvidence(t *testing.T) {
	c, registry, _ := newTestDnsController(t, nil)
	observedAt := time.Now().Add(-5 * time.Second).Truncate(time.Second)
	qi := queryInfo{qname: "signed.example.", qtype: dnsmessage.TypeA}
	address := testARecord(qi.qname, "1.2.3.4")
	address.Hdr.Ttl = 60
	signature := &dnsmessage.RRSIG{
		Hdr:         dnsmessage.RR_Header{Name: qi.qname, Rrtype: dnsmessage.TypeRRSIG, Class: dnsmessage.ClassINET, Ttl: 60},
		TypeCovered: dnsmessage.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 60,
		Inception: uint32(observedAt.Add(-time.Minute).Unix()), Expiration: uint32(observedAt.Add(time.Second).Unix()),
		SignerName: "example.", Signature: "AA==",
	}
	msg := &dnsmessage.Msg{Answer: []dnsmessage.RR{address, signature}}
	c.commitAcceptedResponse(msg, &pendingDNSResponse{
		cacheKey: dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET},
	}, observedAt)
	if registry.Size() != 0 {
		t.Fatalf("expired signed evidence was registered after routing delay: %v", registry.Size())
	}
	if got := msg.Answer[0].Header().Ttl; got != 0 {
		t.Fatalf("expired signed record retained a wire TTL: %v", got)
	}
}

func TestResponsePlanTreatsHighBitTTLAsZero(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	answer := testARecord("example.com.", "1.2.3.4")
	answer.Hdr.Ttl = uint32(math.MaxInt32) + 1
	plan := c.planDNSResponse(queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}, []dnsmessage.RR{answer})
	if got := plan.views[0].answers[0].ttlSeconds; got != 0 {
		t.Fatalf("TTL with the high bit set should be treated as zero: %v", got)
	}
}

func TestResponsePlanBuildsEveryCNAMEChainSuffix(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	first := testCNAMERecord("www.example.", "middle.example.")
	first.Hdr.Ttl = 30
	second := testCNAMERecord("middle.example.", "edge.example.")
	second.Hdr.Ttl = 90
	address := testARecord("edge.example.", "1.2.3.4")
	address.Hdr.Ttl = 300
	plan := c.planDNSResponse(
		queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA},
		[]dnsmessage.RR{first, second, address},
	)

	wantNames := []string{"www.example.", "middle.example.", "edge.example."}
	wantUnitTTLs := []int{30, 90, 0}
	wantWireTTLs := [][]int{{30, 90, 300}, {90, 300}, {300}}
	wantAnswers := []int{3, 2, 1}
	if plan == nil || len(plan.views) != len(wantNames) {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	for i, view := range plan.views {
		if view.query.qname != wantNames[i] || len(view.answers) != wantAnswers[i] {
			t.Errorf("view %v: got %+v", i, view)
			continue
		}
		if view.unitTTLSeconds != wantUnitTTLs[i] {
			t.Errorf("view %v unit TTL: got %v, want %v", i, view.unitTTLSeconds, wantUnitTTLs[i])
		}
		for j, answer := range view.answers {
			if answer.ttlSeconds != wantWireTTLs[i][j] {
				t.Errorf("view %v answer %v TTL: got %v, want %v", i, j, answer.ttlSeconds, wantWireTTLs[i][j])
			}
		}
	}
}

func TestResponsePlanNormalizesRRSetToShortestTTL(t *testing.T) {
	c, registry, fake := newTestDnsController(t, nil)
	long := testARecord("example.com.", "1.2.3.4")
	long.Hdr.Ttl = 300
	shortDuplicate := testARecord("EXAMPLE.COM.", "1.2.3.4")
	shortDuplicate.Hdr.Ttl = 30
	secondAddress := testARecord("example.com.", "5.6.7.8")
	secondAddress.Hdr.Ttl = 120
	now := time.Now()
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	plan := c.planDNSResponse(qi, []dnsmessage.RR{long, shortDuplicate, secondAddress})

	if plan == nil || len(plan.views) != 1 || len(plan.views[0].answers) != 2 {
		t.Fatalf("unexpected normalized plan: %+v", plan)
	}
	for _, answer := range plan.views[0].answers {
		if answer.ttlSeconds != 30 {
			t.Fatalf("one RRset should use its shortest TTL: %+v", plan.views[0].answers)
		}
	}
	msg := &dnsmessage.Msg{Answer: []dnsmessage.RR{long, shortDuplicate, secondAddress}}
	c.commitAcceptedResponse(msg, &pendingDNSResponse{cacheKey: dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}}, now)
	for _, answer := range msg.Answer {
		if answer.Header().Ttl != 30 {
			t.Fatalf("client response did not use the normalized RRset TTL: %+v", msg.Answer)
		}
	}
	for _, ip := range []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")} {
		if got := registry.byName[qi][ip].expiry; !got.Equal(now.Add(30 * time.Second)) {
			t.Errorf("%v expiry: got %v", ip, got)
		}
	}
	checkInvariants(t, registry, fake)
}

func TestResponsePlanAppliesFixedTTLPerView(t *testing.T) {
	c, _, _ := newTestDnsController(t, map[string]int{
		"www.example.":  45,
		"edge.example.": 120,
	})
	cname := testCNAMERecord("www.example.", "edge.example.")
	cname.Hdr.Ttl = 30
	address := testARecord("edge.example.", "1.2.3.4")
	address.Hdr.Ttl = 300
	plan := c.planDNSResponse(
		queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA},
		[]dnsmessage.RR{cname, address},
	)

	if plan == nil || len(plan.views) != 2 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if got := plan.views[0].answers[0].ttlSeconds; got != 45 {
		t.Fatalf("alias fixed_ttl was not applied: %+v", plan.views[0])
	}
	if got := plan.views[0].answers[1].ttlSeconds; got != 120 {
		t.Fatalf("terminal owner fixed_ttl was not preserved in alias response: %+v", plan.views[0])
	}
	if got := plan.views[1].answers[0].ttlSeconds; got != 120 {
		t.Fatalf("terminal fixed_ttl: got %v, want 120", got)
	}
}

func TestResponsePlanCNAMEAAAAKeepsRegistryFloor(t *testing.T) {
	c, registry, fake := newTestDnsController(t, nil)
	cname := testCNAMERecord("www.example.", "edge.example.")
	cname.Hdr.Ttl = 1
	address := testAAAARecord("edge.example.", "2001:db8::1")
	address.Hdr.Ttl = 30
	now := time.Now()
	plan := c.planDNSResponse(
		queryInfo{qname: "www.example.", qtype: dnsmessage.TypeAAAA},
		[]dnsmessage.RR{cname, address},
	)
	c.registerResponsePlan(plan, now)

	ip := netip.MustParseAddr("2001:db8::1")
	aliasQI := queryInfo{qname: "www.example.", qtype: dnsmessage.TypeAAAA}
	targetQI := queryInfo{qname: "edge.example.", qtype: dnsmessage.TypeAAAA}
	if got := registry.byName[aliasQI][ip].expiry; !got.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("alias should retain the registry TTL floor: %v", got)
	}
	if got := registry.byName[targetQI][ip].expiry; !got.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("terminal should retain its RRset TTL: %v", got)
	}
	checkInvariants(t, registry, fake)
}

func TestResponsePlanAtomicallyCachesCNAMEForOtherQtypes(t *testing.T) {
	c, _, _ := newTestDnsController(t, nil)
	cname := testCNAMERecord("www.example.", "edge.example.")
	cname.Hdr.Ttl = 30
	txt := &dnsmessage.TXT{
		Hdr: dnsmessage.RR_Header{Name: "edge.example.", Rrtype: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, Ttl: 300},
		Txt: []string{"value"},
	}
	plan := c.planDNSResponse(
		queryInfo{qname: "www.example.", qtype: dnsmessage.TypeTXT},
		[]dnsmessage.RR{cname, txt},
	)

	if plan == nil || len(plan.views) != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if !plan.views[0].expiresAsUnit || plan.views[0].unitTTLSeconds != 30 {
		t.Fatalf("non-address CNAME response must expire atomically: %+v", plan.views[0])
	}
	if plan.views[0].answers[0].ttlSeconds != 30 || plan.views[0].answers[1].ttlSeconds != 300 {
		t.Fatalf("non-address wire TTLs should remain RRset-specific: %+v", plan.views[0].answers)
	}
}

func TestResponsePlanClassifiesMalformedAndIncompleteCNAME(t *testing.T) {
	t.Run("disconnected cname keeps direct rrset", func(t *testing.T) {
		c, _, _ := newTestDnsController(t, nil)
		address := testARecord("www.example.", "1.2.3.4")
		unrelated := testCNAMERecord("unrelated.example.", "edge.example.")
		plan := c.planDNSResponse(
			queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA},
			[]dnsmessage.RR{address, unrelated},
		)
		if plan == nil || len(plan.views) != 1 || len(plan.views[0].answers) != 1 || len(plan.views[0].addresses) != 1 {
			t.Fatalf("disconnected CNAME should be ignored: %+v", plan)
		}
	})

	t.Run("connected chain without terminal address is not cached", func(t *testing.T) {
		c, _, _ := newTestDnsController(t, nil)
		first := testCNAMERecord("www.example.", "middle.example.")
		first.Hdr.Ttl = 10
		second := testCNAMERecord("middle.example.", "edge.example.")
		second.Hdr.Ttl = 300
		plan := c.planDNSResponse(
			queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA},
			[]dnsmessage.RR{first, second},
		)
		if plan == nil || !plan.suppressCache {
			t.Fatalf("CNAME-to-NODATA must retain wire planning while bypassing the answer-only cache: %+v", plan)
		}
	})

	t.Run("cname owner with direct address is invalid", func(t *testing.T) {
		c, _, _ := newTestDnsController(t, nil)
		if plan := c.planDNSResponse(
			queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA},
			[]dnsmessage.RR{
				testARecord("www.example.", "1.1.1.1"),
				testCNAMERecord("www.example.", "edge.example."),
				testARecord("edge.example.", "2.2.2.2"),
			},
		); plan != nil {
			t.Fatalf("CNAME owner with other data should be rejected: %+v", plan)
		}
	})

	t.Run("non-address conflicting cname is invalid", func(t *testing.T) {
		c, _, _ := newTestDnsController(t, nil)
		if plan := c.planDNSResponse(
			queryInfo{qname: "www.example.", qtype: dnsmessage.TypeTXT},
			[]dnsmessage.RR{
				testCNAMERecord("www.example.", "first.example."),
				testCNAMERecord("www.example.", "second.example."),
			},
		); plan != nil {
			t.Fatalf("conflicting CNAMEs should be rejected for every qtype: %+v", plan)
		}
	})

	t.Run("disconnected cycle is invalid", func(t *testing.T) {
		c, _, _ := newTestDnsController(t, nil)
		if plan := c.planDNSResponse(
			queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA},
			[]dnsmessage.RR{
				testARecord("www.example.", "1.1.1.1"),
				testCNAMERecord("first.example.", "second.example."),
				testCNAMERecord("second.example.", "first.example."),
			},
		); plan != nil {
			t.Fatalf("disconnected malformed CNAME graph should be rejected: %+v", plan)
		}
	})

	tests := []struct {
		name    string
		answers []dnsmessage.RR
	}{
		{
			name: "cycle",
			answers: []dnsmessage.RR{
				testCNAMERecord("www.example.", "edge.example."),
				testCNAMERecord("edge.example.", "www.example."),
			},
		},
		{
			name: "conflicting owner",
			answers: []dnsmessage.RR{
				testCNAMERecord("www.example.", "first.example."),
				testCNAMERecord("www.example.", "second.example."),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _ := newTestDnsController(t, nil)
			if plan := c.planDNSResponse(
				queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA},
				tt.answers,
			); plan != nil {
				t.Fatalf("malformed response should not be cached or registered: %+v", plan)
			}
		})
	}

	t.Run("overlong chain", func(t *testing.T) {
		c, _, _ := newTestDnsController(t, nil)
		answers := make([]dnsmessage.RR, 0, maxCNAMEChainDepth+2)
		for i := 0; i <= maxCNAMEChainDepth; i++ {
			answers = append(answers, testCNAMERecord(
				"name"+strconv.Itoa(i)+".example.",
				"name"+strconv.Itoa(i+1)+".example.",
			))
		}
		if plan := c.planDNSResponse(
			queryInfo{qname: "name0.example.", qtype: dnsmessage.TypeA},
			answers,
		); plan != nil {
			t.Fatalf("overlong response should not be cached or registered: %+v", plan)
		}
	})
}

func TestMalformedResponseStillAppliesFixedTTL(t *testing.T) {
	c, registry, _ := newTestDnsController(t, map[string]int{"www.example.": 15})
	qi := queryInfo{qname: "www.example.", qtype: dnsmessage.TypeA}
	address := testARecord(qi.qname, "1.1.1.1")
	cname := testCNAMERecord(qi.qname, "edge.example.")
	msg := &dnsmessage.Msg{Answer: []dnsmessage.RR{address, cname}}
	key := dnsCacheKey{queryInfo: qi, qclass: dnsmessage.ClassINET}
	c.commitAcceptedResponse(msg, &pendingDNSResponse{cacheKey: key}, time.Now())

	for _, answer := range msg.Answer {
		if answer.Header().Ttl != 15 {
			t.Fatalf("malformed response skipped fixed TTL: %+v", msg.Answer)
		}
	}
	if c.dnsCache.Get(key) != nil || registry.Size() != 0 {
		t.Fatal("malformed response produced cache or routing state")
	}
}

func TestDomainRegistryLeaseDoesNotShrink(t *testing.T) {
	c, registry, fake := newTestDnsController(t, nil)
	qi := queryInfo{qname: "example.com.", qtype: dnsmessage.TypeA}
	ip := netip.MustParseAddr("1.2.3.4")
	firstAt := time.Now()
	long := testARecord(qi.qname, ip.String())
	long.Hdr.Ttl = 300
	c.registerResponsePlan(c.planDNSResponse(qi, []dnsmessage.RR{long}), firstAt)

	short := testARecord(qi.qname, ip.String())
	short.Hdr.Ttl = 30
	c.registerResponsePlan(c.planDNSResponse(qi, []dnsmessage.RR{short}), firstAt.Add(time.Second))
	if got := registry.byName[qi][ip].expiry; !got.Equal(firstAt.Add(300 * time.Second)) {
		t.Fatalf("shorter observation revoked a longer lease: %v", got)
	}
	checkInvariants(t, registry, fake)
}
