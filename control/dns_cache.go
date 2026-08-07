/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"container/list"
	"strings"
	"sync"
	"time"

	dnsmessage "github.com/miekg/dns"
)

type DnsCache struct {
	Answer   dnsmessage.RR
	Deadline time.Time
}

func FillInto(msg *dnsmessage.Msg, caches []*DnsCache) bool {
	now := time.Now()
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
	key   K
	value []*DnsCache
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
		entry.value = liveDnsCaches(entry.value, time.Now())
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

func liveDnsCaches(caches []*DnsCache, now time.Time) []*DnsCache {
	live := make([]*DnsCache, 0, len(caches))
	for _, cache := range caches {
		if cache.Answer != nil && cache.Deadline.After(now) {
			live = append(live, cache)
		}
	}
	return live
}

func (c *commonDnsCache[K]) Delete(cacheKey K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.cache[cacheKey]; ok {
		delete(c.cache, cacheKey)
		c.lruList.Remove(elem)
	}
}

// Len returns the number of cache keys currently held. Keys whose answers
// all expired still count until the LRU gc prunes them: they occupy memory
// and gc pressure is measured against maxSize in the same unit.
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
	lruElement := c.lruList.Back()
	now := time.Now()
	for c.lruList.Len() > c.maxSize {
		if lruElement == nil {
			return
		}
		entry := lruElement.Value.(*cacheEntry[K])
		// Save the previous element before removing current one
		prevElement := lruElement.Prev()
		entry.value = liveDnsCaches(entry.value, now)
		if len(entry.value) == 0 {
			delete(c.cache, entry.key)
			c.lruList.Remove(lruElement)
		}
		lruElement = prevElement
	}
}

func (c *commonDnsCache[K]) UpdateDeadline(key K, answer dnsmessage.RR, deadline time.Time) (cache *DnsCache) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cache = newDnsCache(answer, deadline)

	if elem, ok := c.cache[key]; ok {
		entry := elem.Value.(*cacheEntry[K])
		c.lruList.MoveToFront(elem)
		entry.value = liveDnsCaches(entry.value, time.Now())
		for i, existingCache := range entry.value {
			if c.sameAnswer(existingCache.Answer, cache.Answer) {
				// Replace instead of mutating an object that a concurrent Get
				// may already have returned.
				entry.value[i] = cache
				return cache
			}
		}
		entry.value = append(entry.value, cache)
	} else {
		entry := &cacheEntry[K]{
			key:   key,
			value: []*DnsCache{cache},
		}
		elem := c.lruList.PushFront(entry)
		c.cache[key] = elem
		c.gc()
	}
	return
}

func newDnsCache(answer dnsmessage.RR, deadline time.Time) *DnsCache {
	if answer == nil {
		return &DnsCache{Deadline: deadline}
	}
	answer = dnsmessage.Copy(answer)
	answer.Header().Ttl = 0
	return &DnsCache{Answer: answer, Deadline: deadline}
}

// ReplaceDeadline atomically replaces one key's cached answer set. This is
// the production update path for DNS responses: records absent from the new
// RRset are superseded instead of accumulating as historical values.
func (c *commonDnsCache[K]) ReplaceDeadline(key K, answers []dnsmessage.RR, deadline time.Time) {
	deadlines := make([]time.Time, len(answers))
	for i := range deadlines {
		deadlines[i] = deadline
	}
	c.ReplaceDeadlines(key, answers, deadlines)
}

// ReplaceDeadlines is ReplaceDeadline with one deadline per RR. Ordinary
// RRsets retain independent lifetimes. An answer containing a CNAME is cached
// as one dependent chain, however, and expires at its earliest RR deadline so
// lookup pruning can never return a CNAME without its terminal answer (or a
// terminal answer whose owner no longer matches the question).
func (c *commonDnsCache[K]) ReplaceDeadlines(key K, answers []dnsmessage.RR, deadlines []time.Time) {
	if len(answers) != len(deadlines) {
		panic("DNS answer/deadline length mismatch")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	values := make([]*DnsCache, 0, len(answers))
	for i, answer := range answers {
		if answer == nil {
			continue
		}
		candidate := newDnsCache(answer, deadlines[i])
		duplicate := -1
		for j, existing := range values {
			if c.sameAnswer(existing.Answer, candidate.Answer) {
				duplicate = j
				break
			}
		}
		if duplicate >= 0 {
			if candidate.Deadline.After(values[duplicate].Deadline) {
				values[duplicate] = candidate
			}
			continue
		}
		values = append(values, candidate)
	}
	if len(values) > 1 {
		chainDeadline := time.Time{}
		for _, value := range values {
			if _, ok := value.Answer.(*dnsmessage.CNAME); ok {
				chainDeadline = value.Deadline
				break
			}
		}
		if !chainDeadline.IsZero() {
			for _, value := range values {
				if value.Deadline.Before(chainDeadline) {
					chainDeadline = value.Deadline
				}
			}
			for _, value := range values {
				value.Deadline = chainDeadline
			}
		}
	}

	if elem, ok := c.cache[key]; ok {
		if len(values) == 0 {
			delete(c.cache, key)
			c.lruList.Remove(elem)
			return
		}
		entry := elem.Value.(*cacheEntry[K])
		entry.value = values
		c.lruList.MoveToFront(elem)
		return
	}
	if len(values) == 0 {
		return
	}
	entry := &cacheEntry[K]{key: key, value: values}
	c.cache[key] = c.lruList.PushFront(entry)
	c.gc()
}

// sameAnswer reports whether two RRs are the same record, comparing both the
// header (excluding TTL) and the rdata. Comparing headers alone would
// collapse all A/AAAA records of one name into the first one, dropping every
// other address of a multi-answer response from the cache.
func (c *commonDnsCache[K]) sameAnswer(a, b dnsmessage.RR) bool {
	ha, hb := a.Header(), b.Header()
	if ha.Name != hb.Name || ha.Rrtype != hb.Rrtype || ha.Class != hb.Class {
		return false
	}
	switch aa := a.(type) {
	case *dnsmessage.A:
		bb, ok := b.(*dnsmessage.A)
		return ok && bytes.Equal(aa.A, bb.A)
	case *dnsmessage.AAAA:
		bb, ok := b.(*dnsmessage.AAAA)
		return ok && bytes.Equal(aa.AAAA, bb.AAAA)
	case *dnsmessage.CNAME:
		bb, ok := b.(*dnsmessage.CNAME)
		return ok && strings.EqualFold(aa.Target, bb.Target)
	default:
		// Cached answers have their TTL normalized to zero, so the string
		// form is a safe fallback for the remaining record types.
		return a.String() == b.String()
	}
}

func (c *commonDnsCache[K]) UpdateTtl(key K, answer dnsmessage.RR, ttl int) *DnsCache {
	return c.UpdateDeadline(key, answer, time.Now().Add(time.Duration(ttl)*time.Second))
}
