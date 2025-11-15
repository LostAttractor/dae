/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
)

type DnsCache struct {
	Answer   dnsmessage.RR
	Deadline time.Time
}

// Parse ips from DNS resp answers.
func (c *DnsCache) GetIp() (netip.Addr, bool) {
	var (
		ip netip.Addr
		ok bool
	)
	switch body := c.Answer.(type) {
	case *dnsmessage.A:
		ip, ok = netip.AddrFromSlice(body.A)
	case *dnsmessage.AAAA:
		ip, ok = netip.AddrFromSlice(body.AAAA)
	}
	if !ok || ip.IsUnspecified() {
		return ip, false
	}
	return ip, true
}

func FillInto(msg *dnsmessage.Msg, caches []*DnsCache) {
	for _, cache := range caches {
		if cache.Deadline.After(time.Now()) {
			msg.Answer = append(msg.Answer, deepcopy.Copy(cache.Answer).(dnsmessage.RR))
			msg.Answer[len(msg.Answer)-1].Header().Ttl = uint32(time.Until(cache.Deadline).Seconds())
		}
	}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
}

func IncludeIp(ip netip.Addr, caches []*DnsCache) bool {
	for _, cache := range caches {
		switch body := cache.Answer.(type) {
		case *dnsmessage.A:
			if !ip.Is4() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.A); ok && a == ip {
				return true
			}
		case *dnsmessage.AAAA:
			if !ip.Is6() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.AAAA); ok && a == ip {
				return true
			}
		}
	}
	return false
}

func IncludeAnyIp(caches []*DnsCache) bool {
	for _, cache := range caches {
		switch cache.Answer.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
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
		cache := elem.Value.(*cacheEntry[K]).value
		c.lruList.MoveToFront(elem)
		return cache
	}
	return nil
}

func (c *commonDnsCache[K]) Delete(cacheKey K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.cache[cacheKey]; ok {
		delete(c.cache, cacheKey)
		c.lruList.Remove(elem)
	}
}

func (c *commonDnsCache[K]) AllTimeout(caches []*DnsCache) bool {
	for _, cache := range caches {
		if cache.Deadline.After(time.Now()) {
			return false
		}
	}
	return true
}

// TODO: Delete callback for kernel bpf maps
// gc must be called under write lock
func (c *commonDnsCache[K]) gc() {
	lruElement := c.lruList.Back()
	for c.lruList.Len() > c.maxSize {
		if lruElement == nil {
			return
		}
		entry := lruElement.Value.(*cacheEntry[K])
		// Save the previous element before removing current one
		prevElement := lruElement.Prev()
		if c.AllTimeout(entry.value) {
			delete(c.cache, entry.key)
			c.lruList.Remove(lruElement)
		}
		lruElement = prevElement
	}
}

func (c *commonDnsCache[K]) UpdateDeadline(key K, answer dnsmessage.RR, deadline time.Time) (cache *DnsCache) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cache = &DnsCache{
		Answer:   answer,
		Deadline: deadline,
	}

	if elem, ok := c.cache[key]; ok {
		entry := elem.Value.(*cacheEntry[K])
		c.lruList.MoveToFront(elem)
		for _, c := range entry.value {
			if c.Answer.String() == answer.String() {
				c.Deadline = deadline
				return c
			}
		}
		entry.value = append(entry.value, cache)
		return
	}
	entry := &cacheEntry[K]{
		key:   key,
		value: []*DnsCache{cache},
	}
	elem := c.lruList.PushFront(entry)
	c.cache[key] = elem
	c.gc()
	return
}

func (c *commonDnsCache[K]) UpdateTtl(key K, answer dnsmessage.RR, ttl int) *DnsCache {
	return c.UpdateDeadline(key, answer, time.Now().Add(time.Duration(ttl)*time.Second))
}
