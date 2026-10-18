//go:build !surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"container/list"
	"crypto/sha256"
	"sync"
)

// Only locally compiled bytecode is retained. Each invocation still receives
// a fresh runtime and context, including its own globals and resource limits.
var runtimeBytecode = bytecodeCache{limit: 16 << 20}

type bytecodeEntry struct {
	key  [32]byte
	data []byte
}

type bytecodeCache struct {
	mu           sync.Mutex
	entries      map[[32]byte]*list.Element
	recent       list.List
	bytes, limit int
}

func (c *bytecodeCache) get(source string) []byte {
	key := sha256.Sum256([]byte(source))
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.entries[key]; entry != nil {
		c.recent.MoveToFront(entry)
		return entry.Value.(bytecodeEntry).data
	}
	return nil
}

func (c *bytecodeCache) put(source string, data []byte) {
	if len(data) == 0 || len(data) > c.limit {
		return
	}
	key := sha256.Sum256([]byte(source))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[[32]byte]*list.Element)
	}
	if entry := c.entries[key]; entry != nil {
		c.recent.MoveToFront(entry)
		return
	}
	for c.bytes+len(data) > c.limit || len(c.entries) >= 256 {
		oldest := c.recent.Back()
		entry := oldest.Value.(bytecodeEntry)
		delete(c.entries, entry.key)
		c.bytes -= len(entry.data)
		c.recent.Remove(oldest)
	}
	c.entries[key] = c.recent.PushFront(bytecodeEntry{key, data})
	c.bytes += len(data)
}
