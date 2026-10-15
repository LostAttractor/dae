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
	"os/exec"
	"sync"
	"time"
)

type Pool struct {
	path, bootstrap string
	memoryLimit     int64
	slots           chan struct{}
	done            chan struct{}
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
	p := &Pool{path: resolved, memoryLimit: memoryLimit, bootstrap: bootstrap, slots: make(chan struct{}, size), done: make(chan struct{}), workers: make(map[*worker]struct{}), idleTimeout: time.Minute, sampleInterval: 5 * time.Second}
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
		return fmt.Errorf("nodejs: initialize worker (Node.js 22.13+ is required): %w", err)
	}
	vm.Close()
	if vm.failed {
		return errors.New("nodejs: worker initialization failed")
	}
	return nil
}

func (p *Pool) Acquire(ctx context.Context) (*VM, error) {
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, errors.New("nodejs: runtime is closed")
	}
	p.mu.Lock()
	if p.closed || ctx.Err() != nil {
		p.mu.Unlock()
		<-p.slots
		return nil, cmp.Or(ctx.Err(), errors.New("nodejs: runtime is closed"))
	}
	var w *worker
	fresh := len(p.idle) == 0
	if !fresh {
		w = p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		p.stats.Reused++
	} else {
		var err error
		w, err = startWorker(p.path, p.memoryLimit)
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
		w.close()
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

// Close is safe alongside cancellation and active leases, and reaps children.
func (p *Pool) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.done)
		for w := range p.workers {
			w.close()
		}
		clear(p.workers)
		p.idle = nil
	}
	done := p.monitorDone
	p.mu.Unlock()
	if done != nil {
		<-done
	}
}
