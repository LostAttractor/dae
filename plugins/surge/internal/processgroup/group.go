//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package processgroup

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/containerd/cgroups/v3/cgroup2"
)

type Group struct {
	*cgroup2.Manager
	Path string

	owner    *Group
	removeMu sync.Mutex
	mu       sync.Mutex
	closing  bool
	deleted  bool
	pending  map[*Group]error
	retrying bool
	failure  error
}

func create(parent, name string, limit int64, owner *Group) (group *Group, err error) {
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, err
	}
	group = &Group{Path: path, owner: owner}
	defer func() {
		if err != nil {
			if owner == nil {
				group.closing = true
			}
			// No process has entered a group whose configuration failed.
			err = errors.Join(err, group.rollback())
		}
	}()
	// Load + Update preserves the delegated-controller boundary; NewManager also writes ancestors.
	group.Manager, err = cgroup2.Load("/"+name, cgroup2.WithMountpoint(parent))
	if err != nil {
		return group, err
	}
	if err := group.Update(&cgroup2.Resources{Memory: &cgroup2.Memory{Max: new(limit), Swap: new(int64(0)), OOMGroup: new(owner != nil)}}); err != nil {
		return group, err
	}
	if owner == nil {
		if err := os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), []byte("+memory"), 0600); err != nil {
			return group, err
		}
	}
	return group, nil
}

// NewPool keeps workers inside the daemon's delegated subtree. On failure a
// non-nil group owns unfinished rollback and must not be used to start workers.
func NewPool(kind string, limit int64) (*Group, error) {
	root, current, err := Current()
	if err != nil {
		return nil, fmt.Errorf("Surge %s requires delegated cgroup v2 memory: %w", kind, err)
	}
	parent, err := poolParent(root, current)
	if err != nil {
		return nil, fmt.Errorf("Surge %s requires delegated cgroup v2 memory: %w", kind, err)
	}
	name := fmt.Sprintf("dae-surge-%s-%d-%s", kind, os.Getpid(), rand.Text()[:12])
	group, err := create(parent, name, limit, nil)
	if err != nil {
		return group, fmt.Errorf("create Surge %s memory group in %s: %w", kind, parent, err)
	}
	return group, nil
}
