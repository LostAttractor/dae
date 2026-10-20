// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"container/list"
	"sync"
	"time"
)

// Record values are immutable after insertion; callers copy before changing them.
type Record[V any] struct {
	Value               V
	ReceivedAt, Expires time.Time
}

type stored[K comparable, V any] struct {
	key K
	Record[V]
	bytes int
}

type Stats struct {
	Entries, Limit, Bytes, MemoryLimit int
	Hits, Misses, Expired, Evicted     uint64
}

// Store shares bounded storage between DNS wire answers and script address lists.
// A nonpositive entry limit disables storage; a zero byte limit uses only the
// entry limit. Byte weights include keys and values and are supplied by callers.
type Store[K comparable, V any] struct {
	mu                        sync.Mutex
	entries                   map[K]*list.Element
	lru                       list.List
	limit, memoryLimit, bytes int
	hits, misses              uint64
	expired, evicted          uint64
}

func NewStore[K comparable, V any](entries, memoryBytes int) *Store[K, V] {
	return &Store[K, V]{limit: entries, memoryLimit: memoryBytes}
}

func (s *Store[K, V]) Get(key K, now time.Time) (Record[V], bool) {
	return s.get(key, now, true)
}

// GetIfPresent refreshes hits normally but does not count speculative misses.
func (s *Store[K, V]) GetIfPresent(key K, now time.Time) (Record[V], bool) {
	return s.get(key, now, false)
}

func (s *Store[K, V]) get(key K, now time.Time, countMiss bool) (Record[V], bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if elem := s.entries[key]; elem != nil {
		e := elem.Value.(*stored[K, V])
		if now.Before(e.Expires) {
			s.lru.MoveToFront(elem)
			s.hits++
			return e.Record, true
		}
		s.remove(elem)
		s.expired++
	}
	if countMiss {
		s.misses++
	}
	return Record[V]{}, false
}

// Peek includes expired records and does not change counters, lifetime or LRU.
func (s *Store[K, V]) Peek(key K) (Record[V], bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if elem := s.entries[key]; elem != nil {
		return elem.Value.(*stored[K, V]).Record, true
	}
	return Record[V]{}, false
}

func (s *Store[K, V]) Put(key K, record Record[V], bytes int) bool {
	if s.limit <= 0 || bytes < 0 || s.memoryLimit > 0 && bytes > s.memoryLimit {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[K]*list.Element)
	}
	if old := s.entries[key]; old != nil {
		s.remove(old)
	}
	for len(s.entries) >= s.limit || s.memoryLimit > 0 && bytes > s.memoryLimit-s.bytes {
		s.remove(s.lru.Back())
		s.evicted++
	}
	s.entries[key] = s.lru.PushFront(&stored[K, V]{key: key, Record: record, bytes: bytes})
	s.bytes += bytes
	return true
}

func (s *Store[K, V]) Expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, elem := range s.entries {
		if !now.Before(elem.Value.(*stored[K, V]).Expires) {
			s.remove(elem)
			s.expired++
		}
	}
}

func (s *Store[K, V]) Snapshot() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Entries: len(s.entries), Limit: s.limit, Bytes: s.bytes, MemoryLimit: s.memoryLimit,
		Hits: s.hits, Misses: s.misses, Expired: s.expired, Evicted: s.evicted}
}

func (s *Store[K, V]) remove(elem *list.Element) {
	e := elem.Value.(*stored[K, V])
	delete(s.entries, e.key)
	s.bytes -= e.bytes
	s.lru.Remove(elem)
}
