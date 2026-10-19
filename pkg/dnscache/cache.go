// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"container/list"
	"sync"
	"time"

	dns "github.com/miekg/dns"
)

// Key separates identical questions across resolver and policy namespaces.
type Key struct {
	Namespace string
	Query     Query
}

// Cache is a bounded, memory-only response cache. Keys must include the caller's
// resolver/policy namespace as well as QueryKey. Entries hold immutable packed
// messages; returned messages belong to the caller. No maintenance goroutine is
// needed: expiration is checked on lookup and capacity bounds retained entries.
type Cache struct {
	mu                        sync.Mutex
	entries                   map[Key]*list.Element
	lru                       list.List
	limit, memoryLimit, bytes int
}

type entry struct {
	key      Key
	wire     []byte
	received time.Time
	expires  time.Time
	bytes    int
}

// New creates an entry- and byte-bounded cache. Nonpositive limits disable it.
// The byte budget includes packed data, keys and conservative entry overhead;
// it is not a process RSS limit.
func New(entries, memoryBytes int) *Cache {
	return &Cache{limit: entries, memoryLimit: memoryBytes}
}

func (c *Cache) Get(key Key, now time.Time) (*dns.Msg, bool) {
	c.mu.Lock()
	elem := c.entries[key]
	if elem == nil {
		c.mu.Unlock()
		return nil, false
	}
	e := elem.Value.(*entry)
	if !now.Before(e.expires) {
		c.remove(elem)
		c.mu.Unlock()
		return nil, false
	}
	c.lru.MoveToFront(elem)
	c.mu.Unlock()
	m := new(dns.Msg)
	if err := m.Unpack(e.wire); err != nil {
		return nil, false
	}
	Age(m, uint32(max(0, now.Sub(e.received)/time.Second)))
	return m, true
}

// Put stores an owned, validated and correlated reply. Prepare and packing may
// modify m; no references to it are retained. The caller owns wire validation,
// request correlation and EDNS policy. Receipt time is not renewed by hits.
func (c *Cache) Put(key Key, qtype uint16, m *dns.Msg, received time.Time) bool {
	if c.limit <= 0 || c.memoryLimit <= 0 {
		return false
	}
	ttl := Prepare(qtype, m)
	if ttl == 0 {
		return false
	}
	wire, err := m.Pack()
	bytes := len(wire) + len(key.Namespace) + len(key.Query.Question.Name) + len(key.Query.Options) + 512
	if err != nil || bytes > c.memoryLimit {
		return false
	}
	e := &entry{key: key, wire: wire, received: received, expires: received.Add(time.Duration(ttl) * time.Second), bytes: bytes}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[Key]*list.Element)
	}
	if old := c.entries[key]; old != nil {
		c.remove(old)
	}
	for len(c.entries) >= c.limit || c.bytes+bytes > c.memoryLimit {
		c.remove(c.lru.Back())
	}
	c.entries[key] = c.lru.PushFront(e)
	c.bytes += bytes
	return true
}

func (c *Cache) remove(elem *list.Element) {
	e := elem.Value.(*entry)
	delete(c.entries, e.key)
	c.bytes -= e.bytes
	c.lru.Remove(elem)
}
