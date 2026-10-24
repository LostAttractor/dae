// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
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
	store *Store[Key, []byte]
}

// New creates an entry- and byte-bounded cache. Nonpositive limits disable it.
// The byte budget includes packed data, keys and conservative entry overhead;
// it is not a process RSS limit.
func New(entries, memoryBytes int) *Cache {
	if memoryBytes <= 0 {
		entries = 0
	}
	return &Cache{store: NewStore[Key, []byte](entries, memoryBytes)}
}

// Get also reports when the stored answer expires.
func (c *Cache) Get(key Key, now time.Time) (*dns.Msg, time.Time, bool) {
	e, ok := c.store.Get(key, now)
	if !ok {
		return nil, time.Time{}, false
	}
	m := new(dns.Msg)
	if err := m.Unpack(e.Value); err != nil {
		return nil, time.Time{}, false
	}
	Age(m, uint32(max(0, now.Sub(e.ReceivedAt)/time.Second)))
	return m, e.Expires, true
}

// Put stores an owned, validated and correlated reply. Prepare and packing may
// modify m; no references to it are retained. The caller owns wire validation,
// request correlation and EDNS policy. Receipt time is not renewed by hits.
// Put returns when the stored answer expires, or the zero time if m was not
// stored.
func (c *Cache) Put(key Key, qtype uint16, m *dns.Msg, received time.Time) time.Time {
	if c.store.limit <= 0 || c.store.memoryLimit <= 0 {
		return time.Time{}
	}
	ttl := Prepare(qtype, m)
	if ttl == 0 {
		return time.Time{}
	}
	wire, err := m.Pack()
	bytes := len(wire) + len(key.Namespace) + len(key.Query.Question.Name) + len(key.Query.Options) + 512
	if err != nil || bytes > c.store.memoryLimit {
		return time.Time{}
	}
	expires := received.Add(time.Duration(ttl) * time.Second)
	if !c.store.Put(key, Record[[]byte]{Value: wire, ReceivedAt: received, Expires: expires}, bytes) {
		return time.Time{}
	}
	return expires
}
