/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/list"
	"reflect"
	"sync"
	"time"

	dnsmessage "github.com/miekg/dns"
)

type DnsCache struct {
	Answer   dnsmessage.RR
	Deadline time.Time
}

type dnsAnswerKey struct {
	name   string
	rrtype uint16
	class  uint16
	rdata  string
}

// dnsQueryVariant returns a collision-free wire fingerprint for every
// response-varying part of a conventional one-question query except qname and
// qtype, which are represented directly in dnsCacheKey. Keeping those two
// fields out of the fingerprint lets a derived CNAME target key retain QCLASS,
// header flags, EDNS version/size/flags, and every supported EDNS option.
func dnsQueryVariant(msg *dnsmessage.Msg) (string, bool) {
	if msg == nil || msg.Response || msg.Opcode != dnsmessage.OpcodeQuery ||
		msg.Authoritative || msg.Truncated || msg.RecursionAvailable || msg.Zero ||
		msg.Rcode != dnsmessage.RcodeSuccess || len(msg.Question) != 1 ||
		len(msg.Answer) != 0 || len(msg.Ns) != 0 {
		return "", false
	}
	if _, ok := dnsmessage.IsDomainName(msg.Question[0].Name); !ok || !dnsmessage.IsFqdn(msg.Question[0].Name) {
		return "", false
	}
	switch msg.Question[0].Qtype {
	case dnsmessage.TypeAXFR, dnsmessage.TypeIXFR, dnsmessage.TypeTKEY:
		return "", false
	}
	if len(msg.Extra) > 1 {
		return "", false
	}
	if len(msg.Extra) == 1 {
		opt, ok := msg.Extra[0].(*dnsmessage.OPT)
		if !ok || opt == nil || opt.Hdr.Rrtype != dnsmessage.TypeOPT || opt.Hdr.Name != "." {
			return "", false
		}
		for _, option := range opt.Option {
			if nilEDNSQueryOption(option) || !supportedEDNSQueryOption(option) {
				return "", false
			}
		}
	}

	canonical := msg.Copy()
	canonical.Id = 0
	canonical.Compress = false
	canonical.Question[0].Name = "."
	canonical.Question[0].Qtype = 0
	canonical.Question[0].Qclass = 0
	wire, err := canonical.Pack()
	if err != nil || len(wire) > 4096 {
		return "", false
	}
	return string(wire), true
}

func nilEDNSQueryOption(option dnsmessage.EDNS0) bool {
	if option == nil {
		return true
	}
	v := reflect.ValueOf(option)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

func supportedEDNSQueryOption(option dnsmessage.EDNS0) bool {
	switch option.(type) {
	case *dnsmessage.EDNS0_NSID,
		*dnsmessage.EDNS0_SUBNET,
		*dnsmessage.EDNS0_DAU,
		*dnsmessage.EDNS0_DHU,
		*dnsmessage.EDNS0_N3U,
		*dnsmessage.EDNS0_PADDING,
		*dnsmessage.EDNS0_EDE,
		*dnsmessage.EDNS0_ESU:
		return true
	default:
		// EDNS0_LOCAL represents options whose semantics this code does not
		// know. Bypass caching/coalescing instead of risking normalization
		// that aliases two response-varying requests.
		return false
	}
}

// The answer-only persistent cache cannot reconstruct a response OPT record.
// Queries carrying OPT therefore use exact-key flight sharing but bypass the
// persistent cache. Non-IN responses are also kept out of domain routing and
// the cache.
func dnsQueryCacheable(msg *dnsmessage.Msg) bool {
	return msg != nil && len(msg.Question) == 1 &&
		msg.Question[0].Qclass == dnsmessage.ClassINET && len(msg.Extra) == 0
}

func fillDnsCacheInto(msg *dnsmessage.Msg, caches []*DnsCache, now time.Time) bool {
	appended := false
	for _, cache := range caches {
		if cache.Deadline.After(now) && cache.Answer != nil {
			msg.Answer = append(msg.Answer, dnsmessage.Copy(cache.Answer))
			msg.Answer[len(msg.Answer)-1].Header().Ttl = uint32(cache.Deadline.Sub(now).Seconds())
			appended = true
		}
	}
	if !appended {
		return false
	}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
	// AD=1 in a request only asks for authenticated data; echoing it in a
	// cached response would falsely assert that dae validated the answer.
	msg.AuthenticatedData = false
	return true
}

func IncludeAnyIpInMsg(msg *dnsmessage.Msg) bool {
	for _, ans := range msg.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}

type cacheEntry[K comparable] struct {
	key        K
	value      []*DnsCache
	validUntil time.Time
}

type commonDnsCache[K comparable] struct {
	cache   map[K]*list.Element
	lruList *list.List
	mu      sync.Mutex
	maxSize int
}

func newCommonDnsCache[K comparable](maxSize int) *commonDnsCache[K] {
	return &commonDnsCache[K]{
		cache:   make(map[K]*list.Element),
		lruList: list.New(),
		maxSize: maxSize,
	}
}

func (c *commonDnsCache[K]) Get(cacheKey K) []*DnsCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.cache[cacheKey]; ok {
		entry := elem.Value.(*cacheEntry[K])
		now := time.Now()
		if !entry.validUntil.IsZero() && !entry.validUntil.After(now) {
			delete(c.cache, cacheKey)
			c.lruList.Remove(elem)
			return nil
		}
		entry.value = liveDnsCaches(entry.value, now)
		if len(entry.value) == 0 {
			delete(c.cache, cacheKey)
			c.lruList.Remove(elem)
			return nil
		}
		c.lruList.MoveToFront(elem)
		// Do not expose the entry's backing slice: updates may compact or
		// replace it after this lock is released.
		return append([]*DnsCache(nil), entry.value...)
	}
	return nil
}

// FillInto validates dependency and record deadlines under one lock, so a
// CNAME entry cannot cross its unit deadline between lookup and response fill.
func (c *commonDnsCache[K]) FillInto(cacheKey K, msg *dnsmessage.Msg) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.cache[cacheKey]
	if !ok {
		return false
	}
	entry := elem.Value.(*cacheEntry[K])
	now := time.Now()
	if !entry.validUntil.IsZero() && !entry.validUntil.After(now) {
		delete(c.cache, cacheKey)
		c.lruList.Remove(elem)
		return false
	}
	entry.value = liveDnsCaches(entry.value, now)
	if len(entry.value) == 0 {
		delete(c.cache, cacheKey)
		c.lruList.Remove(elem)
		return false
	}
	c.lruList.MoveToFront(elem)
	return fillDnsCacheInto(msg, entry.value, now)
}

func liveDnsCaches(caches []*DnsCache, now time.Time) []*DnsCache {
	live := caches[:0]
	for _, cache := range caches {
		if cache.Answer != nil && cache.Deadline.After(now) {
			live = append(live, cache)
		}
	}
	clear(caches[len(live):])
	return live
}

// Len returns the number of cache keys currently held. Naturally expired keys
// count until they are read or evicted because they still occupy memory.
func (c *commonDnsCache[K]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

// MaxSize returns the key-count limit the LRU gc enforces.
func (c *commonDnsCache[K]) MaxSize() int {
	return c.maxSize
}

// gc must be called with c.mu held.
func (c *commonDnsCache[K]) gc() {
	// Enforce the hard cap in O(1) per eviction. Expired answers are discarded
	// when their key is read or replaced; scanning every key here would turn
	// each post-cap insertion into an O(maxSize) operation under the cache lock.
	for c.lruList.Len() > c.maxSize {
		elem := c.lruList.Back()
		if elem == nil {
			return
		}
		entry := elem.Value.(*cacheEntry[K])
		delete(c.cache, entry.key)
		c.lruList.Remove(elem)
	}
}

func newDnsCache(answer dnsmessage.RR, deadline time.Time) *DnsCache {
	if answer == nil {
		return &DnsCache{Deadline: deadline}
	}
	answer = dnsmessage.Copy(answer)
	answer.Header().Ttl = 0
	return &DnsCache{Answer: answer, Deadline: deadline}
}

// Replace atomically replaces one key's prepared answer set. validUntil is an
// optional dependency deadline for records, such as one complete CNAME chain.
func (c *commonDnsCache[K]) Replace(key K, values []*DnsCache, validUntil time.Time) {
	prepared := make([]*DnsCache, 0, len(values))
	for _, value := range values {
		if value == nil || value.Answer == nil {
			continue
		}
		prepared = append(prepared, value)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if !validUntil.IsZero() && !validUntil.After(now) {
		prepared = nil
	} else {
		prepared = liveDnsCaches(prepared, now)
	}
	if elem, ok := c.cache[key]; ok {
		if len(prepared) == 0 {
			delete(c.cache, key)
			c.lruList.Remove(elem)
			return
		}
		entry := elem.Value.(*cacheEntry[K])
		entry.value = prepared
		entry.validUntil = validUntil
		c.lruList.MoveToFront(elem)
		return
	}
	if len(prepared) == 0 {
		return
	}
	entry := &cacheEntry[K]{key: key, value: prepared, validUntil: validUntil}
	c.cache[key] = c.lruList.PushFront(entry)
	c.gc()
}

func dnsAnswerIdentity(answer dnsmessage.RR) dnsAnswerKey {
	header := answer.Header()
	key := dnsAnswerKey{
		name:   dnsmessage.CanonicalName(header.Name),
		rrtype: header.Rrtype,
		class:  header.Class,
	}
	switch body := answer.(type) {
	case *dnsmessage.A:
		key.rdata = string(body.A)
	case *dnsmessage.AAAA:
		key.rdata = string(body.AAAA)
	case *dnsmessage.CNAME:
		key.rdata = dnsmessage.CanonicalName(body.Target)
	default:
		copied := dnsmessage.Copy(answer)
		copied.Header().Name = key.name
		copied.Header().Ttl = 0
		key.rdata = copied.String()
	}
	return key
}
