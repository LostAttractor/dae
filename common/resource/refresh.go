// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"context"
	"sync"
	"time"
)

// RefreshStore retains the accepted resource groups and their next checks.
// Begin and Commit are serialized by the owner; a session supports parallel loads.
// This working set is independent of optional persistence in Cache.Dir.
type RefreshStore struct {
	groups map[string]refreshGroup
}

type refreshGroup struct {
	snapshot *cacheSnapshot
	checks   map[string]refreshCheck
	fallback bool
}

type refreshCheck struct {
	interval time.Duration
	due      time.Time
}

type RefreshSession struct {
	store    *RefreshStore
	previous map[string]refreshGroup
	interval time.Duration
	dueOnly  bool
	mu       sync.Mutex
	groups   map[string]refreshGroup
}

type refreshContextKey struct{}

// Begin prepares a new working set. dueOnly reuses remote resources whose
// checks are not due; explicit reloads and refresh requests pass false.
func (s *RefreshStore) Begin(ctx context.Context, interval time.Duration, dueOnly bool) (context.Context, *RefreshSession) {
	r := &RefreshSession{store: s, previous: s.groups, interval: interval, dueOnly: dueOnly, groups: make(map[string]refreshGroup)}
	return context.WithValue(ctx, refreshContextKey{}, r), r
}

// Commit publishes only groups used by the accepted configuration, releasing
// removed resources and their schedules. Abandoned sessions have no effect.
func (r *RefreshSession) Commit() { r.store.groups = r.groups }

func (s *RefreshStore) Next() time.Time {
	var next time.Time
	for _, group := range s.groups {
		for _, check := range group.checks {
			if !check.due.IsZero() && (next.IsZero() || check.due.Before(next)) {
				next = check.due
			}
		}
	}
	return next
}

func refreshSession(ctx context.Context) *RefreshSession {
	if session, ok := ctx.Value(refreshContextKey{}).(*RefreshSession); ok {
		return session
	}
	// Standalone loads use the same path, with no previous working set to publish.
	return &RefreshSession{groups: make(map[string]refreshGroup)}
}

func (r *RefreshSession) stage(key string, snapshot *cacheSnapshot, checks map[string]refreshCheck, fallback bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groups[key] = refreshGroup{snapshot: snapshot, checks: checks, fallback: fallback}
}

// Fallbacks reports groups kept at their previous revision after a failed check.
func (r *RefreshSession) Fallbacks() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, group := range r.groups {
		if group.fallback {
			count++
		}
	}
	return count
}

func (r *RefreshSession) readInterval(options ReadOptions) time.Duration {
	if options.RefreshInterval != nil {
		return *options.RefreshInterval
	}
	return r.interval
}

func (c refreshCheck) reschedule(failed bool) refreshCheck {
	if c.interval == 0 {
		return c
	}
	interval := c.interval
	if failed {
		interval = min(interval, 5*time.Minute)
	}
	c.due = time.Now().Add(interval)
	return c
}
