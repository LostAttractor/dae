// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

// The pool is shared by Surge instances and overlapping configuration generations.
// Capacity includes starting processes and workers being killed/reaped.
type Pool struct {
	group    *processgroup.Group
	ctx      context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
	queue    chan struct{}
	mu       sync.Mutex
	idle     []*worker
	jobs     sync.WaitGroup
	sequence atomic.Uint64
	closed   chan struct{} // closed once the last release finishes close
}

var shared struct {
	sync.Mutex
	pool       *Pool
	references int
}

func Acquire() (*Pool, func() error, error) {
	shared.Lock()
	defer shared.Unlock()
	// A retained pool with no references exists only to finish cleanup.
	for shared.pool != nil && shared.references == 0 {
		if closed := shared.pool.closed; closed != nil && !isClosed(closed) {
			// Wait for the last release to finish closing it, which keeps
			// workers within one pool's memory, instead of failing.
			shared.Unlock()
			<-closed
			shared.Lock()
			continue
		}
		if !shared.pool.group.Deleted() {
			return nil, nil, errors.Join(ErrUnavailable, shared.pool.group.Check(), shared.pool.group.CleanupError())
		}
		shared.pool = nil
	}
	if shared.pool == nil {
		group, err := processgroup.NewPool("jq", PoolMemory)
		if err != nil {
			if group != nil {
				// Failed initialization may still own resources being retried by Group.
				shared.pool = &Pool{group: group}
			}
			return nil, nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		shared.pool = &Pool{group: group, ctx: ctx, cancel: cancel, slots: make(chan struct{}, MaxWorkers), queue: make(chan struct{}, MaxWorkers+16), closed: make(chan struct{})}
	}
	pool := shared.pool
	if err := pool.group.Check(); err != nil {
		return nil, nil, err
	}
	shared.references++
	release := sync.OnceValue(func() error {
		shared.Lock()
		shared.references--
		if shared.references != 0 {
			shared.Unlock()
			return nil
		}
		pool.mu.Lock()
		pool.cancel()
		pool.mu.Unlock()
		shared.Unlock()
		defer close(pool.closed)
		return pool.close()
	})
	return pool, release, nil
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func (p *Pool) close() error {
	p.jobs.Wait()
	// Each job either returns its worker to idle or closes it before finishing.
	var err error
	for _, w := range p.idle {
		err = errors.Join(err, w.Close())
	}
	p.idle = nil
	return errors.Join(err, p.group.Delete())
}

func (p *Pool) Validate(ctx context.Context, expression string) error {
	_, err := p.run(ctx, expression, nil, 1, nil, true)
	return err
}

func (p *Pool) Apply(ctx context.Context, expression string, body []byte, limit int64, budget *membuffer.Budget) (*membuffer.View, error) {
	return p.run(ctx, expression, body, limit, budget, false)
}

func (p *Pool) run(parent context.Context, expression string, body []byte, limit int64, budget *membuffer.Budget, validate bool) (result *membuffer.View, err error) {
	if p == nil {
		return nil, ErrUnavailable
	}
	if len(expression) == 0 || len(expression) > MaxExpression {
		return nil, errors.New("invalid jq expression size")
	}
	if limit <= 0 || limit > MaxBody || int64(len(body)) > limit {
		return nil, membuffer.ErrTooLarge
	}
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			result.Close()
			result, err = nil, ctx.Err()
		}
	}()
	stopPool := context.AfterFunc(p.ctx, cancel)
	defer stopPool()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, ErrUnavailable
	}
	p.jobs.Add(1)
	p.mu.Unlock()
	defer p.jobs.Done()
	select {
	case p.queue <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	defer func() { <-p.queue }()
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-p.slots }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.group.Check(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	var w *worker
	if len(p.idle) != 0 {
		w = p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
	}
	p.mu.Unlock()
	if w == nil {
		w, err = p.start()
		if err != nil {
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = w.Close() })
	healthy := false
	defer func() {
		if stop() && healthy && ctx.Err() == nil {
			p.mu.Lock()
			p.idle = append(p.idle, w)
			p.mu.Unlock()
			return
		}
		// Close joins cancellation and returns its cached error before releasing the slot.
		err = errors.Join(err, w.Close())
		if w.OOMKilled {
			err = fmt.Errorf("jq worker: %w", errors.Join(processgroup.ErrOOMKilled, err))
		}
	}()
	request := frame{Magic: frameMagic, Generation: w.generation, Job: p.sequence.Add(1), Expression: uint32(len(expression)), Body: uint32(len(body)), Limit: uint32(limit)}
	if validate {
		request.Validate = 1
	}
	if err := writeFrame(w.Input, request); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w.Input, expression); err != nil {
		return nil, err
	}
	if _, err := w.Input.Write(body); err != nil {
		return nil, err
	}
	response, err := readFrame(w.Output)
	if err != nil {
		return nil, fmt.Errorf("jq worker exited or returned an invalid frame: %w", err)
	}
	if response.Generation != request.Generation || response.Job != request.Job {
		return nil, errors.New("stale jq worker result")
	}
	switch response.Status {
	case statusEmpty:
		if response.Body != 0 {
			return nil, errors.New("invalid empty jq response")
		}
		healthy = true
		return nil, nil
	case statusOK:
		if validate || response.Body == 0 || int64(response.Body) > limit {
			return nil, membuffer.ErrTooLarge
		}
		result, err = membuffer.Read(io.LimitReader(w.Output, int64(response.Body)), int64(response.Body), budget)
		if err == nil && len(result.Bytes()) != int(response.Body) {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			result.Close()
			return nil, err
		}
		healthy = true
		return result, nil
	case statusError, statusLarge:
		if response.Body > maxError {
			return nil, errors.New("invalid jq error length")
		}
		data := make([]byte, response.Body)
		if _, err := io.ReadFull(w.Output, data); err != nil {
			return nil, err
		}
		healthy = true
		if response.Status == statusLarge {
			return nil, membuffer.ErrTooLarge
		}
		return nil, responseError(data)
	default:
		return nil, errors.New("unknown jq worker response")
	}
}

type worker struct {
	*processgroup.Process
	generation uint64
}

func (p *Pool) start() (*worker, error) {
	id := p.sequence.Add(1)
	// The installed path can point to a different image after deployment.
	command := exec.Command("/proc/self/exe", "plugins", "surge", "__jq-worker")
	command.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=96MiB", "LANG=C.UTF-8"}
	process, err := p.group.Start(command, WorkerMemory)
	if err != nil {
		return nil, fmt.Errorf("start memory constrained jq worker: %w", err)
	}
	return &worker{Process: process, generation: id}, nil
}
