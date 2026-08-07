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

func testARecord(name string, ip string) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	}
}

func testCNAMERecord(name, target string) *dnsmessage.CNAME {
	return &dnsmessage.CNAME{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeCNAME,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		Target: target,
	}
}

func TestCommonDnsCache_UpdateAndGet(t *testing.T) {
	c := newCommonDnsCache[string](4)
	answer := testARecord("example.com.", "1.2.3.4")
	c.UpdateTtl("key1", answer, 60)

	caches := c.Get("key1")
	if len(caches) != 1 || !c.sameAnswer(caches[0].Answer, answer) {
		t.Fatalf("Get: got %+v", caches)
	}
	if c.Get("nonexistent") != nil {
		t.Errorf("Get of a missing key should return nil")
	}
}

func TestCommonDnsCache_UpdateSameAnswer(t *testing.T) {
	c := newCommonDnsCache[string](4)
	answer := testARecord("example.com.", "1.2.3.4")
	c.UpdateTtl("key1", answer, 60)
	// Updating the same answer refreshes the deadline in
	// place instead of appending a duplicate.
	c.UpdateTtl("key1", answer, 120)

	caches := c.Get("key1")
	if len(caches) != 1 {
		t.Fatalf("duplicated answer headers should be merged: got %v caches", len(caches))
	}
	if caches[0].Deadline.Before(time.Now().Add(100 * time.Second)) {
		t.Errorf("deadline should be refreshed: got %v", caches[0].Deadline)
	}
}

func TestCommonDnsCache_UpdateDifferentAnswers(t *testing.T) {
	c := newCommonDnsCache[string](4)
	c.UpdateTtl("key1", testARecord("example.com.", "1.2.3.4"), 60)
	c.UpdateTtl("key1", &dnsmessage.AAAA{
		Hdr: dnsmessage.RR_Header{
			Name:   "example.com.",
			Rrtype: dnsmessage.TypeAAAA,
			Class:  dnsmessage.ClassINET,
		},
		AAAA: net.ParseIP("::1"),
	}, 60)

	if caches := c.Get("key1"); len(caches) != 2 {
		t.Fatalf("answers with different headers should both be cached: got %v caches", len(caches))
	}
}

func TestCommonDnsCache_LruEviction(t *testing.T) {
	c := newCommonDnsCache[string](2)
	expired := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)

	// The expired entry is also the least recently used entry.
	c.UpdateDeadline("key1", testARecord("a.com.", "1.1.1.1"), expired)
	c.UpdateDeadline("key2", testARecord("b.com.", "2.2.2.2"), future)
	c.UpdateDeadline("key3", testARecord("c.com.", "3.3.3.3"), future)

	if c.Get("key1") != nil {
		t.Errorf("expired least-recently-used entry should be evicted")
	}
	if c.Get("key2") == nil || c.Get("key3") == nil {
		t.Errorf("fresh entries should be kept")
	}
}

func TestCommonDnsCache_LruHardCapEvictsLive(t *testing.T) {
	c := newCommonDnsCache[string](2)
	future := time.Now().Add(time.Minute)

	// All entries are live; the oldest must still be evicted once the cache
	// grows past maxSize.
	c.UpdateDeadline("key1", testARecord("a.com.", "1.1.1.1"), future)
	c.UpdateDeadline("key2", testARecord("b.com.", "2.2.2.2"), future)
	c.UpdateDeadline("key3", testARecord("c.com.", "3.3.3.3"), future)

	if c.Len() != 2 {
		t.Fatalf("cache should be capped at maxSize: got %v entries", c.Len())
	}
	if c.Get("key1") != nil {
		t.Errorf("least-recently-used live entry should be evicted")
	}
	if c.Get("key2") == nil || c.Get("key3") == nil {
		t.Errorf("recent live entries should be kept")
	}
}

func TestCommonDnsCache_HardCapDoesNotCompactEveryLiveEntry(t *testing.T) {
	c := newCommonDnsCache[string](2)
	future := time.Now().Add(time.Minute)
	c.UpdateDeadline("key1", testARecord("a.com.", "1.1.1.1"), future)
	c.UpdateDeadline("key2", testARecord("b.com.", "2.2.2.2"), future)

	entry := c.cache["key2"].Value.(*cacheEntry[string])
	valueBefore := &entry.value[0]
	c.UpdateDeadline("key3", testARecord("c.com.", "3.3.3.3"), future)

	entry = c.cache["key2"].Value.(*cacheEntry[string])
	if valueAfter := &entry.value[0]; valueAfter != valueBefore {
		t.Fatal("hard-cap eviction compacted an unrelated live entry")
	}
}

func TestCommonDnsCache_ExpiredReplacementDoesNotEvictLiveEntry(t *testing.T) {
	c := newCommonDnsCache[string](2)
	future := time.Now().Add(time.Minute)
	c.ReplaceDeadline("key1", []dnsmessage.RR{testARecord("a.com.", "1.1.1.1")}, future)
	c.ReplaceDeadline("key2", []dnsmessage.RR{testARecord("b.com.", "2.2.2.2")}, future)
	c.ReplaceDeadline("key3", []dnsmessage.RR{testARecord("c.com.", "3.3.3.3")}, time.Now())

	if c.Len() != 2 || c.Get("key1") == nil || c.Get("key2") == nil {
		t.Fatalf("expired replacement evicted a live entry: len=%d", c.Len())
	}
	if c.Get("key3") != nil {
		t.Fatal("expired replacement should not occupy the cache")
	}
}

func TestCommonDnsCache_LruOrder(t *testing.T) {
	c := newCommonDnsCache[string](2)
	expired := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)

	c.UpdateDeadline("key1", testARecord("a.com.", "1.1.1.1"), future)
	c.UpdateDeadline("key2", testARecord("b.com.", "2.2.2.2"), expired)
	// Touch key1 so key2 becomes the least recently used.
	c.Get("key1")
	c.UpdateDeadline("key3", testARecord("c.com.", "3.3.3.3"), expired)

	if c.Get("key2") != nil {
		t.Errorf("key2 is the least recently used and should be evicted first")
	}
	if c.Get("key1") == nil {
		t.Errorf("key1 was recently used and should be kept")
	}
}

func TestCommonDnsCache_GetPrunesIndividualExpiredAnswers(t *testing.T) {
	c := newCommonDnsCache[string](4)
	future := time.Now().Add(time.Minute)
	expired := time.Now().Add(-time.Minute)
	c.UpdateDeadline("key1", testARecord("example.com.", "1.1.1.1"), future)
	c.UpdateDeadline("key1", testARecord("example.com.", "2.2.2.2"), expired)

	caches := c.Get("key1")
	if len(caches) != 1 || !cacheIncludesA(caches, "1.1.1.1") {
		t.Fatalf("Get should retain only the live answer: %v", caches)
	}
	entry := c.cache["key1"].Value.(*cacheEntry[string])
	if len(entry.value) != 1 {
		t.Fatalf("expired answer should be removed from storage: %v", len(entry.value))
	}
}

func TestCommonDnsCache_CNAMEChainExpiresAsUnit(t *testing.T) {
	now := time.Now()
	expired := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	answers := []dnsmessage.RR{
		testCNAMERecord("example.com.", "target.example."),
		testARecord("target.example.", "1.1.1.1"),
	}
	tests := []struct {
		name      string
		deadlines []time.Time
	}{
		{name: "cname expired", deadlines: []time.Time{expired, future}},
		{name: "terminal expired", deadlines: []time.Time{future, expired}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCommonDnsCache[string](4)
			c.ReplaceDeadlines("key1", answers, tt.deadlines)
			if caches := c.Get("key1"); caches != nil {
				t.Fatalf("an incomplete CNAME chain must miss the cache: %v", caches)
			}
			if _, ok := c.cache["key1"]; ok {
				t.Fatal("expired CNAME chain should be removed from storage")
			}
		})
	}
}

func TestCommonDnsCache_ReplaceRRSetDropsHistoricalAnswers(t *testing.T) {
	c := newCommonDnsCache[string](4)
	future := time.Now().Add(time.Minute)
	c.ReplaceDeadline("key1", []dnsmessage.RR{
		testARecord("example.com.", "1.1.1.1"),
		testARecord("example.com.", "2.2.2.2"),
	}, future)
	c.ReplaceDeadline("key1", []dnsmessage.RR{
		testARecord("example.com.", "2.2.2.2"),
		testARecord("example.com.", "3.3.3.3"),
	}, future)

	caches := c.Get("key1")
	if len(caches) != 2 || cacheIncludesA(caches, "1.1.1.1") ||
		!cacheIncludesA(caches, "2.2.2.2") || !cacheIncludesA(caches, "3.3.3.3") {
		t.Fatalf("cache should contain exactly the current RRset: %v", caches)
	}

	// A fixed_ttl=0 replacement removes the old RRset and never occupies the cache.
	expired := time.Now()
	for i := 1; i <= 100; i++ {
		c.ReplaceDeadline("key1", []dnsmessage.RR{
			testARecord("example.com.", fmt.Sprintf("10.0.0.%d", i)),
		}, expired)
	}
	if _, ok := c.cache["key1"]; ok {
		t.Fatal("rotating zero-TTL answers must not remain in storage")
	}
}

func TestCommonDnsCache_Delete(t *testing.T) {
	c := newCommonDnsCache[string](4)
	c.UpdateTtl("key1", testARecord("example.com.", "1.2.3.4"), 60)
	c.Delete("key1")
	if c.Get("key1") != nil {
		t.Errorf("deleted entry should not be returned")
	}
	// Deleting a missing key should not panic.
	c.Delete("nonexistent")
}

func TestCommonDnsCache_FillIntoSkipsExpired(t *testing.T) {
	var caches []*DnsCache
	c := newCommonDnsCache[string](4)
	caches = append(caches, c.UpdateTtl("key1", testARecord("a.com.", "1.1.1.1"), 60))
	caches = append(caches, c.UpdateDeadline("key1", testARecord("b.com.", "2.2.2.2"), time.Now().Add(-time.Minute)))

	msg := new(dnsmessage.Msg)
	FillInto(msg, caches)
	if len(msg.Answer) != 1 {
		t.Fatalf("expired answers should be skipped: got %v answers", len(msg.Answer))
	}
	if !msg.Response || msg.Rcode != dnsmessage.RcodeSuccess {
		t.Errorf("FillInto should mark the message as a successful response")
	}
	ttl := msg.Answer[0].Header().Ttl
	if ttl == 0 || ttl > 60 {
		t.Errorf("ttl should be recomputed from the deadline: got %v", ttl)
	}
}

func TestCommonDnsCache_MultiARecordsSameName(t *testing.T) {
	// Regression: a response with multiple A records for the same name must
	// cache every address. Header-only dedup used to drop all but the first.
	c := newCommonDnsCache[string](4)
	c.UpdateTtl("key1", testARecord("example.com.", "1.1.1.1"), 60)
	c.UpdateTtl("key1", testARecord("example.com.", "2.2.2.2"), 60)
	c.UpdateTtl("key1", testARecord("example.com.", "3.3.3.3"), 60)

	caches := c.Get("key1")
	if len(caches) != 3 {
		t.Fatalf("all A records of the same name should be cached: got %v", len(caches))
	}

	// Refreshing one address must not duplicate it nor touch the others.
	c.UpdateTtl("key1", testARecord("example.com.", "2.2.2.2"), 120)
	caches = c.Get("key1")
	if len(caches) != 3 {
		t.Fatalf("refreshing an existing record should not duplicate: got %v", len(caches))
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if !cacheIncludesA(caches, ip) {
			t.Errorf("cached answers should include %v", ip)
		}
	}
}
