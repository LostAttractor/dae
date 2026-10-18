//go:build !surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import "testing"

func TestBytecodeCacheEvictsBySizeAndRecency(t *testing.T) {
	cache := bytecodeCache{limit: 8}
	cache.put("a", []byte{1, 2, 3})
	cache.put("b", []byte{4, 5, 6})
	if cache.get("a") == nil {
		t.Fatal("cache miss")
	}
	cache.put("c", []byte{7, 8, 9})
	if cache.get("a") == nil || cache.get("b") != nil || cache.get("c") == nil || cache.bytes != 6 {
		t.Fatal("cache exceeded budget or evicted the most recent entry")
	}
	cache.put("large", make([]byte, 9))
	if cache.get("large") != nil || cache.bytes != 6 {
		t.Fatal("oversized bytecode was retained")
	}
}
