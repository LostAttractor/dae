//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package processgroup

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const cleanupWait = time.Second

var (
	ErrCleanup   = errors.New("processgroup: resource cleanup failed")
	ErrOOMKilled = errors.New("processgroup: process killed by the kernel OOM killer")
)

func (g *Group) root() *Group {
	if g.owner != nil {
		return g.owner
	}
	return g
}

// Check rejects new work while cleanup is pending, but not after recovery.
func (g *Group) Check() error {
	root := g.root()
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.closing {
		return fmt.Errorf("processgroup: pool %s is closed: %w", root.Path, errors.Join(os.ErrClosed, root.failure))
	}
	for _, err := range root.pending {
		return err
	}
	return nil
}

// CleanupError retains the first failure even after all resources are reclaimed.
func (g *Group) CleanupError() error {
	root := g.root()
	root.mu.Lock()
	defer root.mu.Unlock()
	return root.failure
}

func (g *Group) Deleted() bool {
	root := g.root()
	root.mu.Lock()
	defer root.mu.Unlock()
	return g.deleted
}

func (g *Group) remember(err error) {
	root := g.root()
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.failure == nil {
		root.failure = err
	}
}

func (g *Group) finished() {
	root := g.root()
	root.mu.Lock()
	defer root.mu.Unlock()
	g.deleted = true
	delete(root.pending, g)
}

func (g *Group) pendingCleanup(err error) error {
	err = fmt.Errorf("%w for %s: %w", ErrCleanup, g.Path, err)
	root := g.root()
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.failure == nil {
		root.failure = err
	}
	if g.deleted {
		return err
	}
	if root.pending == nil {
		root.pending = make(map[*Group]error)
	}
	root.pending[g] = err
	if !root.retrying {
		root.retrying = true
		go root.retryCleanup()
	}
	return err
}

// Kill uses the supported kernel interface; the library's legacy fallback can
// reap exec.Cmd's child behind its back when a cgroup.kill write fails.
func (g *Group) Kill() error {
	return os.WriteFile(filepath.Join(g.Path, "cgroup.kill"), []byte("1"), 0600)
}

// Delete either removes the group or transfers it to its pool's cleanup owner.
func (g *Group) Delete() error {
	if g.owner == nil {
		g.mu.Lock()
		g.closing = true
		g.mu.Unlock()
	}
	err := g.remove(true)
	if err != nil {
		err = g.pendingCleanup(err)
	}
	if g.owner == nil {
		err = errors.Join(err, g.CleanupError())
	}
	return err
}

// rollback cannot wait: callers may still hold their pool's admission lock.
func (g *Group) rollback() error {
	g.removeMu.Lock()
	defer g.removeMu.Unlock()
	if err := os.Remove(g.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return g.pendingCleanup(err)
	}
	g.finished()
	return nil
}

func (g *Group) populated() (bool, error) {
	data, err := os.ReadFile(filepath.Join(g.Path, "cgroup.events"))
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			switch fields[1] {
			case "0":
				return false, nil
			case "1":
				return true, nil
			}
		}
	}
	return false, errors.New("missing or invalid populated in cgroup.events")
}

func (g *Group) remove(wait bool) error {
	g.removeMu.Lock()
	defer g.removeMu.Unlock()
	if g.Deleted() {
		return nil
	}
	deadline := time.Now().Add(cleanupWait)
	for {
		populated, err := g.populated()
		if err != nil {
			if _, statErr := os.Stat(g.Path); errors.Is(statErr, os.ErrNotExist) {
				g.finished()
				return nil
			}
			return err
		}
		if populated {
			err = errors.New("cgroup still contains running processes")
		} else if g.Manager != nil {
			err = g.Manager.Delete()
		} else {
			err = os.Remove(g.Path)
		}
		if err == nil {
			g.finished()
			return nil
		}
		if !wait || errors.Is(err, os.ErrPermission) || time.Until(deadline) <= 0 {
			return err
		}
		time.Sleep(min(10*time.Millisecond, time.Until(deadline)))
	}
}

func (g *Group) retryCleanup() {
	for delay := time.Second; ; delay = min(2*delay, time.Minute) {
		time.Sleep(delay)
		g.mu.Lock()
		pending := slices.Collect(maps.Keys(g.pending))
		g.mu.Unlock()
		for _, child := range pending {
			if child.Manager != nil && !child.Deleted() {
				_ = child.Kill()
			}
			_ = child.remove(false)
		}
		g.mu.Lock()
		if len(g.pending) == 0 {
			g.retrying = false
			g.mu.Unlock()
			return
		}
		g.mu.Unlock()
	}
}
