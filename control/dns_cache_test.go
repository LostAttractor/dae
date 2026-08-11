/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// cacheIncludesA reports whether the caches contain an A record for ip.
func cacheIncludesA(caches []*DnsCache, ip string) bool {
	want := net.ParseIP(ip).To4()
	for _, cache := range caches {
		if a, ok := cache.Answer.(*dnsmessage.A); ok && bytes.Equal(a.A, want) {
			return true
		}
	}
	return false
}

func testCommonCacheKey(key string) dnsCacheKey {
	return dnsCacheKey{queryInfo: queryInfo{qname: key}}
}

func replaceTestCache(c *commonDnsCache, key string, answers []dnsmessage.RR, deadline time.Time) {
	values := make([]*DnsCache, 0, len(answers))
	for _, answer := range answers {
		values = append(values, newDnsCache(answer, deadline))
	}
	c.Replace(testCommonCacheKey(key), values, time.Time{})
}

func replaceTestCacheDeadlines(c *commonDnsCache, key string, answers []dnsmessage.RR, deadlines []time.Time) {
	values := make([]*DnsCache, 0, len(answers))
	for i, answer := range answers {
		values = append(values, newDnsCache(answer, deadlines[i]))
	}
	c.Replace(testCommonCacheKey(key), values, time.Time{})
}

func TestCommonDnsCache_UpdateAndGet(t *testing.T) {
	c := newCommonDnsCache(4)
	answer := testARecord("example.com.", "1.2.3.4")
	replaceTestCache(c, "key1", []dnsmessage.RR{answer}, time.Now().Add(time.Minute))

	caches := getTestDNSCache(c, testCommonCacheKey("key1"))
	if len(caches) != 1 || dnsAnswerIdentity(caches[0].Answer) != dnsAnswerIdentity(answer) {
		t.Fatalf("Get: got %+v", caches)
	}
	if getTestDNSCache(c, testCommonCacheKey("nonexistent")) != nil {
		t.Errorf("Get of a missing key should return nil")
	}
}

func TestCommonDnsCache_UpdateSameAnswer(t *testing.T) {
	c := newCommonDnsCache(4)
	answer := testARecord("example.com.", "1.2.3.4")
	replaceTestCache(c, "key1", []dnsmessage.RR{answer}, time.Now().Add(time.Minute))
	// Replacing the same answer refreshes its deadline without retaining a
	// historical duplicate.
	replaceTestCache(c, "key1", []dnsmessage.RR{answer}, time.Now().Add(2*time.Minute))

	caches := getTestDNSCache(c, testCommonCacheKey("key1"))
	if len(caches) != 1 {
		t.Fatalf("duplicated answer headers should be merged: got %v caches", len(caches))
	}
	if caches[0].Deadline.Before(time.Now().Add(100 * time.Second)) {
		t.Errorf("deadline should be refreshed: got %v", caches[0].Deadline)
	}
}

func TestCommonDnsCache_UpdateDifferentAnswers(t *testing.T) {
	c := newCommonDnsCache(4)
	replaceTestCacheDeadlines(c, "key1", []dnsmessage.RR{
		testARecord("example.com.", "1.2.3.4"),
		&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeAAAA,
				Class:  dnsmessage.ClassINET,
			},
			AAAA: net.ParseIP("::1"),
		}}, []time.Time{time.Now().Add(time.Minute), time.Now().Add(time.Minute)})

	if caches := getTestDNSCache(c, testCommonCacheKey("key1")); len(caches) != 2 {
		t.Fatalf("answers with different headers should both be cached: got %v caches", len(caches))
	}
}

func TestCommonDnsCache_ExpiredInsertDoesNotConsumeCapacity(t *testing.T) {
	c := newCommonDnsCache(2)
	expired := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)

	// An already-expired replacement is discarded before it can force a live
	// entry through hard-cap eviction.
	replaceTestCache(c, "key1", []dnsmessage.RR{testARecord("a.com.", "1.1.1.1")}, expired)
	replaceTestCache(c, "key2", []dnsmessage.RR{testARecord("b.com.", "2.2.2.2")}, future)
	replaceTestCache(c, "key3", []dnsmessage.RR{testARecord("c.com.", "3.3.3.3")}, future)

	if getTestDNSCache(c, testCommonCacheKey("key1")) != nil {
		t.Errorf("expired entry should not be stored")
	}
	if getTestDNSCache(c, testCommonCacheKey("key2")) == nil || getTestDNSCache(c, testCommonCacheKey("key3")) == nil {
		t.Errorf("fresh entries should be kept")
	}
}

func TestCommonDnsCache_LruHardCapEvictsLive(t *testing.T) {
	c := newCommonDnsCache(2)
	future := time.Now().Add(time.Minute)

	// All entries are live; the oldest must still be evicted once the cache
	// grows past maxSize.
	replaceTestCache(c, "key1", []dnsmessage.RR{testARecord("a.com.", "1.1.1.1")}, future)
	replaceTestCache(c, "key2", []dnsmessage.RR{testARecord("b.com.", "2.2.2.2")}, future)
	replaceTestCache(c, "key3", []dnsmessage.RR{testARecord("c.com.", "3.3.3.3")}, future)

	if c.Len() != 2 {
		t.Fatalf("cache should be capped at maxSize: got %v entries", c.Len())
	}
	if getTestDNSCache(c, testCommonCacheKey("key1")) != nil {
		t.Errorf("least-recently-used live entry should be evicted")
	}
	if getTestDNSCache(c, testCommonCacheKey("key2")) == nil || getTestDNSCache(c, testCommonCacheKey("key3")) == nil {
		t.Errorf("recent live entries should be kept")
	}
}

func TestCommonDnsCache_HardCapDoesNotCompactEveryLiveEntry(t *testing.T) {
	c := newCommonDnsCache(2)
	future := time.Now().Add(time.Minute)
	replaceTestCache(c, "key1", []dnsmessage.RR{testARecord("a.com.", "1.1.1.1")}, future)
	replaceTestCache(c, "key2", []dnsmessage.RR{testARecord("b.com.", "2.2.2.2")}, future)

	entry := c.cache[testCommonCacheKey("key2")].Value.(*cacheEntry)
	valueBefore := &entry.value[0]
	replaceTestCache(c, "key3", []dnsmessage.RR{testARecord("c.com.", "3.3.3.3")}, future)

	entry = c.cache[testCommonCacheKey("key2")].Value.(*cacheEntry)
	if valueAfter := &entry.value[0]; valueAfter != valueBefore {
		t.Fatal("hard-cap eviction compacted an unrelated live entry")
	}
}

func TestCommonDnsCache_ExpiredDependencyDoesNotEvictLiveEntry(t *testing.T) {
	c := newCommonDnsCache(2)
	future := time.Now().Add(time.Minute)
	replaceTestCache(c, "key1", []dnsmessage.RR{testARecord("a.com.", "1.1.1.1")}, future)
	replaceTestCache(c, "key2", []dnsmessage.RR{testARecord("b.com.", "2.2.2.2")}, future)
	c.Replace(testCommonCacheKey("key3"), []*DnsCache{
		newDnsCache(testARecord("c.com.", "3.3.3.3"), future),
	}, time.Now())

	if c.Len() != 2 || getTestDNSCache(c, testCommonCacheKey("key1")) == nil || getTestDNSCache(c, testCommonCacheKey("key2")) == nil {
		t.Fatalf("expired dependency evicted a live entry: len=%d", c.Len())
	}
	if getTestDNSCache(c, testCommonCacheKey("key3")) != nil {
		t.Fatal("expired dependency should not occupy the cache")
	}
}

func TestCommonDnsCache_LruOrder(t *testing.T) {
	c := newCommonDnsCache(2)
	future := time.Now().Add(time.Minute)

	replaceTestCache(c, "key1", []dnsmessage.RR{testARecord("a.com.", "1.1.1.1")}, future)
	replaceTestCache(c, "key2", []dnsmessage.RR{testARecord("b.com.", "2.2.2.2")}, future)
	// Touch key1 so key2 becomes the least recently used.
	getTestDNSCache(c, testCommonCacheKey("key1"))
	replaceTestCache(c, "key3", []dnsmessage.RR{testARecord("c.com.", "3.3.3.3")}, future)

	if getTestDNSCache(c, testCommonCacheKey("key2")) != nil {
		t.Errorf("key2 is the least recently used and should be evicted first")
	}
	if getTestDNSCache(c, testCommonCacheKey("key1")) == nil {
		t.Errorf("key1 was recently used and should be kept")
	}
}

func TestCommonDnsCache_GetPrunesIndividualExpiredAnswers(t *testing.T) {
	c := newCommonDnsCache(4)
	future := time.Now().Add(time.Minute)
	answers := []dnsmessage.RR{
		testARecord("example.com.", "1.1.1.1"),
		testARecord("example.com.", "2.2.2.2"),
	}
	replaceTestCache(c, "key1", answers, future)
	entry := c.cache[testCommonCacheKey("key1")].Value.(*cacheEntry)
	entry.value[1].Deadline = time.Now().Add(-time.Minute)

	caches := getTestDNSCache(c, testCommonCacheKey("key1"))
	if len(caches) != 1 || !cacheIncludesA(caches, "1.1.1.1") {
		t.Fatalf("Get should retain only the live answer: %v", caches)
	}
	entry = c.cache[testCommonCacheKey("key1")].Value.(*cacheEntry)
	if len(entry.value) != 1 {
		t.Fatalf("expired answer should be removed from storage: %v", len(entry.value))
	}
}

func TestCommonDnsCache_ReplaceRRSetDropsHistoricalAnswers(t *testing.T) {
	c := newCommonDnsCache(4)
	future := time.Now().Add(time.Minute)
	replaceTestCache(c, "key1", []dnsmessage.RR{
		testARecord("example.com.", "1.1.1.1"),
		testARecord("example.com.", "2.2.2.2"),
	}, future)
	replaceTestCache(c, "key1", []dnsmessage.RR{
		testARecord("example.com.", "2.2.2.2"),
		testARecord("example.com.", "3.3.3.3"),
	}, future)

	caches := getTestDNSCache(c, testCommonCacheKey("key1"))
	if len(caches) != 2 || cacheIncludesA(caches, "1.1.1.1") ||
		!cacheIncludesA(caches, "2.2.2.2") || !cacheIncludesA(caches, "3.3.3.3") {
		t.Fatalf("cache should contain exactly the current RRset: %v", caches)
	}

	// A fixed_ttl=0 replacement removes the old RRset and never occupies the cache.
	expired := time.Now()
	for i := 1; i <= 100; i++ {
		replaceTestCache(c, "key1", []dnsmessage.RR{
			testARecord("example.com.", fmt.Sprintf("10.0.0.%d", i)),
		}, expired)
	}
	if _, ok := c.cache[testCommonCacheKey("key1")]; ok {
		t.Fatal("rotating zero-TTL answers must not remain in storage")
	}
}

func TestCommonDnsCache_FillIntoSkipsExpired(t *testing.T) {
	c := newCommonDnsCache(4)
	future := time.Now().Add(time.Minute)
	c.Replace(testCommonCacheKey("key1"), []*DnsCache{
		newDnsCache(testARecord("a.com.", "1.1.1.1"), future),
		newDnsCache(testARecord("b.com.", "2.2.2.2"), future),
	}, time.Time{})
	c.cache[testCommonCacheKey("key1")].Value.(*cacheEntry).value[1].Deadline = time.Now().Add(-time.Minute)

	msg := &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{AuthenticatedData: true}}
	if !c.FillInto(testCommonCacheKey("key1"), msg) {
		t.Fatal("live cache entry should fill the response")
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expired answers should be skipped: got %v answers", len(msg.Answer))
	}
	if !msg.Response || msg.Rcode != dnsmessage.RcodeSuccess {
		t.Errorf("FillInto should mark the message as a successful response")
	}
	if msg.AuthenticatedData {
		t.Error("cache hit must not echo the query AD bit as an authentication assertion")
	}
	ttl := msg.Answer[0].Header().Ttl
	if ttl == 0 || ttl > 60 {
		t.Errorf("ttl should be recomputed from the deadline: got %v", ttl)
	}
}

func TestCommonDnsCache_FillIntoHonorsUnitDeadline(t *testing.T) {
	c := newCommonDnsCache(4)
	c.Replace(testCommonCacheKey("key1"), []*DnsCache{
		newDnsCache(testARecord("a.com.", "1.1.1.1"), time.Now().Add(time.Minute)),
	}, time.Now().Add(time.Minute))
	c.cache[testCommonCacheKey("key1")].Value.(*cacheEntry).validUntil = time.Now().Add(-time.Minute)

	msg := new(dnsmessage.Msg)
	if c.FillInto(testCommonCacheKey("key1"), msg) {
		t.Fatal("expired dependency deadline should miss the cache")
	}
	if len(msg.Answer) != 0 {
		t.Fatalf("expired dependency appended answers: %+v", msg.Answer)
	}
	if _, ok := c.cache[testCommonCacheKey("key1")]; ok {
		t.Fatal("expired dependency should be removed from storage")
	}
}

func TestCommonDnsCache_MultiARecordsSameName(t *testing.T) {
	// Regression: a response with multiple A records for the same name must
	// cache every address. Header-only dedup used to drop all but the first.
	c := newCommonDnsCache(4)
	answers := []dnsmessage.RR{
		testARecord("example.com.", "1.1.1.1"),
		testARecord("example.com.", "2.2.2.2"),
		testARecord("example.com.", "3.3.3.3"),
	}
	replaceTestCache(c, "key1", answers, time.Now().Add(time.Minute))

	caches := getTestDNSCache(c, testCommonCacheKey("key1"))
	if len(caches) != 3 {
		t.Fatalf("all A records of the same name should be cached: got %v", len(caches))
	}

	// Replacing the RRset must keep every address without duplication.
	replaceTestCacheDeadlines(c, "key1", answers, []time.Time{
		time.Now().Add(time.Minute),
		time.Now().Add(2 * time.Minute),
		time.Now().Add(time.Minute),
	})
	caches = getTestDNSCache(c, testCommonCacheKey("key1"))
	if len(caches) != 3 {
		t.Fatalf("refreshing an existing record should not duplicate: got %v", len(caches))
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if !cacheIncludesA(caches, ip) {
			t.Errorf("cached answers should include %v", ip)
		}
	}
}
