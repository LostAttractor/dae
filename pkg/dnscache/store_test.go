// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"testing"
	"time"
)

func TestStorePeekDoesNotChangeLRUOrCounters(t *testing.T) {
	s := NewStore[string, string](2, 10)
	now := time.Now()
	record := Record[string]{Value: "answer", ReceivedAt: now, Expires: now.Add(time.Minute)}
	s.Put("a", record, 4)
	s.Put("b", record, 4)
	before := s.Snapshot()
	if got, ok := s.Peek("a"); !ok || got != record || s.Snapshot() != before {
		t.Fatal("peek changed the record or counters")
	}
	s.Put("c", record, 4)
	if _, ok := s.Peek("a"); ok {
		t.Fatal("peek changed LRU order")
	}
	if got := s.Snapshot(); got.Entries != 2 || got.Bytes != 8 || got.Evicted != 1 {
		t.Fatalf("capacity accounting: %+v", got)
	}
	if _, ok := s.Get("b", record.Expires); ok {
		t.Fatal("expired entry was returned")
	}
	if _, ok := s.Peek("b"); ok {
		t.Fatal("lookup retained expired entry")
	}
	s.Expire(record.Expires)
	if got := s.Snapshot(); got.Entries != 0 || got.Bytes != 0 || got.Expired != 2 || got.Misses != 1 {
		t.Fatalf("expiration accounting: %+v", got)
	}
}

func TestStoreReplacementAndEntryOnlyBudget(t *testing.T) {
	s := NewStore[int, string](1, 0)
	now := time.Now()
	record := Record[string]{Value: "first", ReceivedAt: now, Expires: now.Add(time.Minute)}
	s.Put(1, record, 10)
	record.Value = "replacement"
	s.Put(1, record, 20)
	if got := s.Snapshot(); got.Entries != 1 || got.Bytes != 20 || got.Evicted != 0 {
		t.Fatalf("replacement accounting: %+v", got)
	}
	if got, ok := s.Get(1, now); !ok || got.Value != "replacement" || s.Snapshot().Hits != 1 {
		t.Fatal("replacement not returned")
	}
	s.Put(2, record, 30)
	if got := s.Snapshot(); got.Entries != 1 || got.Bytes != 30 || got.Evicted != 1 {
		t.Fatalf("entry-only budget: %+v", got)
	}
}

func TestStoreSpeculativeLookupCountsOnlyHits(t *testing.T) {
	s := NewStore[string, string](2, 0)
	now := time.Now()
	record := Record[string]{Value: "answer", ReceivedAt: now, Expires: now.Add(time.Minute)}
	s.Put("a", record, 1)
	s.Put("b", record, 1)
	if _, hit := s.GetIfPresent("absent", now); hit || s.Snapshot().Misses != 0 {
		t.Fatal("speculative miss counted as an exchange")
	}
	if got, hit := s.GetIfPresent("a", now); !hit || got != record || s.Snapshot().Hits != 1 {
		t.Fatal("speculative hit was not counted")
	}
	s.Put("c", record, 1)
	if _, present := s.Peek("b"); present {
		t.Fatal("speculative hit did not refresh LRU order")
	}
	if _, hit := s.GetIfPresent("a", record.Expires); hit {
		t.Fatal("speculative lookup returned an expired answer")
	}
	if stats := s.Snapshot(); stats.Misses != 0 || stats.Expired != 1 || stats.Entries != 1 {
		t.Fatalf("speculative expiry accounting: %+v", stats)
	}
}
