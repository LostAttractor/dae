/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type TimedWaitGroup struct {
	wg        sync.WaitGroup
	mu        sync.Mutex
	counter   uint64
	itemsByID map[uint64]*twgItem
}

type twgItem struct {
	timer   *time.Timer
	message string
	timeout time.Duration
	done    bool
}

// NewTimedWaitGroup creates a new TimedWaitGroup instance.
func NewTimedWaitGroup() *TimedWaitGroup {
	return &TimedWaitGroup{
		itemsByID: make(map[uint64]*twgItem),
	}
}

// Add registers a new item with a timeout and a message.
// It returns an id which must be provided to Done when the item completes.
func (t *TimedWaitGroup) Add(timeout time.Duration, message string) uint64 {
	id := atomic.AddUint64(&t.counter, 1)
	t.wg.Add(1)

	item := &twgItem{message: message, timeout: timeout}

	// Create timer first so we can store it in the map before it fires.
	item.timer = time.AfterFunc(timeout, func() {
		t.mu.Lock()
		item, exists := t.itemsByID[id]
		// Prevent logging if already done.
		if exists && !item.done {
			log.Warnln("task too long: ", item.message)
		}
		t.mu.Unlock()
	})

	t.mu.Lock()
	t.itemsByID[id] = item
	t.mu.Unlock()

	return id
}

// Done marks the item identified by id as completed. It stops the item's timer
// and decrements the underlying wait group. Calling Done with an unknown id is
// a no-op.
func (t *TimedWaitGroup) Done(id uint64) {
	t.mu.Lock()
	item := t.itemsByID[id]
	delete(t.itemsByID, id)
	item.done = true
	// Stop timer outside of map to avoid holding lock during potential callback races.
	t.mu.Unlock()
	item.timer.Stop()
	t.wg.Done()
}

// Wait blocks until all added items have called Done.
func (t *TimedWaitGroup) Wait() {
	t.wg.Wait()
}
