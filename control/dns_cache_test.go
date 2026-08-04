/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func mustParseAddr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

func testARecord(name string, ip string) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
		},
		A: net.ParseIP(ip).To4(),
	}
}

func TestDnsCacheGetIp(t *testing.T) {
	cache := &DnsCache{Answer: testARecord("example.com.", "1.2.3.4")}
	ip, ok := cache.GetIp()
	if !ok || ip.String() != "1.2.3.4" {
		t.Errorf("GetIp: got %v, %v", ip, ok)
	}

	cache = &DnsCache{Answer: &dnsmessage.AAAA{
		Hdr: dnsmessage.RR_Header{
			Name:   "example.com.",
			Rrtype: dnsmessage.TypeAAAA,
			Class:  dnsmessage.ClassINET,
		},
		AAAA: net.ParseIP("::1"),
	}}
	if _, ok = cache.GetIp(); !ok {
		t.Errorf("GetIp should parse AAAA records")
	}

	// Unspecified addresses are invalid.
	cache = &DnsCache{Answer: testARecord("example.com.", "0.0.0.0")}
	if _, ok = cache.GetIp(); ok {
		t.Errorf("GetIp should reject unspecified addresses")
	}
}

func TestCommonDnsCache_UpdateAndGet(t *testing.T) {
	c := newCommonDnsCache[string](4)
	answer := testARecord("example.com.", "1.2.3.4")
	c.UpdateTtl("key1", answer, 60)

	caches := c.Get("key1")
	if len(caches) != 1 || caches[0].Answer != answer {
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
	// Updating an answer with the same header refreshes the deadline in
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

	// gc only evicts entries whose answers all timed out.
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

func TestCommonDnsCache_LruOrder(t *testing.T) {
	c := newCommonDnsCache[string](2)
	expired := time.Now().Add(-time.Minute)

	c.UpdateDeadline("key1", testARecord("a.com.", "1.1.1.1"), expired)
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

func TestCommonDnsCache_IncludeIp(t *testing.T) {
	c := newCommonDnsCache[string](4)
	caches := []*DnsCache{
		c.UpdateTtl("key1", testARecord("a.com.", "1.1.1.1"), 60),
	}
	if !IncludeIp(mustParseAddr("1.1.1.1"), caches) {
		t.Errorf("IncludeIp should find the cached address")
	}
	if IncludeIp(mustParseAddr("9.9.9.9"), caches) {
		t.Errorf("IncludeIp should not find an unknown address")
	}
	if !IncludeAnyIp(caches) {
		t.Errorf("IncludeAnyIp should be true for A/AAAA caches")
	}
}
