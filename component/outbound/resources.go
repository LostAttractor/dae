// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import "sync"

// Resources owns group references held by active and prepared control planes.
// Resource keys describe effective construction inputs, never routing IDs.
type Resources struct {
	Paths  PathPool
	mu     sync.Mutex
	groups map[string]*groupResource
}

type groupResource struct {
	group *DialerGroup
	refs  int
}

func (r *Resources) Acquire(key string, build func() (*DialerGroup, error)) (*DialerGroup, func() error, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups == nil {
		r.groups = make(map[string]*groupResource)
	}
	entry := r.groups[key]
	if entry == nil {
		group, err := build()
		if err != nil {
			return nil, nil, err
		}
		entry = &groupResource{group: group}
		r.groups[key] = entry
	}
	entry.refs++
	release := sync.OnceValue(func() error {
		r.mu.Lock()
		entry.refs--
		last := entry.refs == 0
		if last {
			delete(r.groups, key)
		}
		r.mu.Unlock()
		if last {
			err := entry.group.Close()
			r.Paths.prune()
			return err
		}
		return nil
	})
	return entry.group, release, nil
}
