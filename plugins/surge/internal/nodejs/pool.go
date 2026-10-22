//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

// Package nodejs runs the Surge host protocol in reusable Node.js processes.
// Each lease owns a fresh context; a failed or interrupted process is discarded.
package nodejs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

type Pool struct {
	path, bootstrap string
	memoryLimit     int64
	workerMemory    int64
	poolMemory      int64
	group           *processgroup.Group
	groupErr        error
	cleanupErr      error
	slots           chan struct{}
	done            chan struct{}
	changed         chan struct{}
	closeOnce       func() error
	mu              sync.Mutex
	closed          bool
	idle            []*worker
	workers         map[*worker]struct{}
	monitorDone     chan struct{}
	idleTimeout     time.Duration
	sampleInterval  time.Duration
	stats           Stats
}

// NewPool validates settings and resolves the executable without starting any
// processes. Warm initializes one reusable worker during preparation or preflight.
func NewPool(ctx context.Context, path string, memoryLimit int64, size int, bootstrap string) (*Pool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if memoryLimit < 16<<20 || memoryLimit > 1<<30 {
		return nil, errors.New("nodejs: memory limit must be between 16 MiB and 1 GiB")
	}
	if size < 1 || size > 256 {
		return nil, errors.New("nodejs: worker count must be between 1 and 256")
	}
	resolved, err := exec.LookPath(cmp.Or(path, "node"))
	if err != nil {
		return nil, fmt.Errorf("nodejs: find executable: %w", err)
	}
	// shortcut: fixed runtime headroom; calibrate on target Node versions before production use.
	workerMemory := 2*memoryLimit + (64 << 20)
	// Leave one worker budget for delayed kernel charges from retired processes.
	p := &Pool{
		path: resolved, bootstrap: bootstrap,
		memoryLimit: memoryLimit, workerMemory: workerMemory,
		poolMemory: workerMemory * int64(size+1),
		slots:      make(chan struct{}, size), done: make(chan struct{}),
		workers:     make(map[*worker]struct{}),
		idleTimeout: time.Minute, sampleInterval: 5 * time.Second,
	}
	p.closeOnce = sync.OnceValue(p.close)
	return p, nil
}

// Warm initializes the worker protocol and compiles the shared bootstrap without
// executing user scripts. Preflight uses a disposable pool; serving pools retain
// this worker and count it in the same statistics as demand-created workers.
func (p *Pool) Warm(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	vm, err := p.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("nodejs: initialize worker: %w", err)
	}
	vm.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(ctx); err != nil {
		return err
	}
	if vm.failed {
		return errors.Join(errors.New("nodejs: worker initialization failed"), p.cleanupErr)
	}
	return nil
}

func (p *Pool) checkLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.closed {
		return errors.New("nodejs: runtime is closed")
	}
	if p.groupErr != nil {
		return p.groupErr
	}
	if p.group != nil {
		return p.group.Check()
	}
	return nil
}

func (p *Pool) Acquire(ctx context.Context) (*VM, error) {
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, cmp.Or(ctx.Err(), errors.New("nodejs: runtime is closed"))
	}
	p.mu.Lock()
	for {
		if err := p.checkLocked(ctx); err != nil {
			p.mu.Unlock()
			<-p.slots
			return nil, err
		}
		if len(p.idle) != 0 || len(p.workers) < cap(p.slots) {
			break
		}
		if p.changed == nil {
			p.changed = make(chan struct{})
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		case <-p.done:
		}
		p.mu.Lock()
	}
	var w *worker
	fresh := len(p.idle) == 0
	if !fresh {
		w = p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		p.stats.Reused++
	} else {
		var err error
		w, err = p.startWorker()
		if err != nil {
			p.stats.StartFailures++
			p.mu.Unlock()
			<-p.slots
			return nil, fmt.Errorf("nodejs: start worker: %w", err)
		}
		p.workers[w] = struct{}{}
		p.stats.Started++
	}
	if p.monitorDone == nil {
		p.monitorDone = make(chan struct{})
		go p.monitor()
	}
	p.mu.Unlock()
	vm := &VM{pool: p, worker: w, ctx: ctx, interrupted: make(chan struct{})}
	vm.stop = context.AfterFunc(ctx, func() {
		p.closeWorker(w)
		close(vm.interrupted)
	})
	if fresh {
		if err := vm.command(command{Op: "init", Text: p.bootstrap}); err != nil {
			vm.Close()
			return nil, err
		}
	}
	return vm, nil
}

// closeWorker never holds the pool lock while joining process cleanup.
func (p *Pool) closeWorker(w *worker) error {
	p.mu.Lock()
	w.retiring = true
	p.mu.Unlock()
	err := w.Close()
	p.mu.Lock()
	if p.cleanupErr == nil {
		p.cleanupErr = err
	}
	p.mu.Unlock()
	return err
}

func (p *Pool) notifyLocked() {
	if p.changed != nil {
		close(p.changed)
		p.changed = nil
	}
}

// Close is safe alongside cancellation and active leases, and joins all callers.
func (p *Pool) Close() error { return p.closeOnce() }

func (p *Pool) close() error {
	p.mu.Lock()
	p.closed = true
	close(p.done)
	workers := slices.Collect(maps.Keys(p.workers))
	for _, w := range workers {
		w.retiring = true
	}
	p.idle = nil
	done := p.monitorDone
	p.mu.Unlock()

	for _, w := range workers {
		p.closeWorker(w)
	}
	if done != nil {
		<-done
	}
	p.mu.Lock()
	clear(p.workers)
	p.sampleCgroupLocked()
	p.mu.Unlock()

	var err error
	if p.group != nil {
		err = p.group.Delete()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.group != nil && p.group.Deleted() {
		p.stats.CgroupMemoryBytes = 0
	}
	return errors.Join(p.cleanupErr, err)
}
