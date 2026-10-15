// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

// The pool is shared by Surge instances and overlapping configuration generations.
// Capacity includes starting processes and workers being killed/reaped.
type Pool struct {
	group      *memoryGroup
	executable string
	ctx        context.Context
	cancel     context.CancelFunc
	slots      chan struct{}
	queue      chan struct{}
	mu         sync.Mutex
	idle       []*worker
	jobs       sync.WaitGroup
	sequence   atomic.Uint64
}

var shared struct {
	sync.Mutex
	pool       *Pool
	references int
}

func Acquire() (*Pool, func() error, error) {
	shared.Lock()
	defer shared.Unlock()
	if shared.pool == nil {
		group, err := newPoolGroup()
		if err != nil {
			return nil, nil, err
		}
		executable, err := os.Executable()
		if err != nil {
			_ = group.close()
			return nil, nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		shared.pool = &Pool{group: group, executable: executable, ctx: ctx, cancel: cancel, slots: make(chan struct{}, MaxWorkers), queue: make(chan struct{}, MaxWorkers+16)}
	}
	shared.references++
	pool := shared.pool
	release := sync.OnceValue(func() error {
		shared.Lock()
		defer shared.Unlock()
		shared.references--
		if shared.references != 0 {
			return nil
		}
		err := pool.close()
		shared.pool = nil
		return err
	})
	return pool, release, nil
}

func (p *Pool) close() error {
	p.mu.Lock()
	p.cancel()
	p.mu.Unlock()
	p.jobs.Wait()
	// Each job either returns its worker to idle or closes it before finishing.
	for _, w := range p.idle {
		w.close()
	}
	p.idle = nil
	return p.group.close()
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
	stop := context.AfterFunc(ctx, w.close)
	healthy := false
	defer func() {
		stop()
		if ctx.Err() != nil {
			result.Close()
			result, err = nil, ctx.Err()
			healthy = false
		}
		if healthy {
			p.mu.Lock()
			p.idle = append(p.idle, w)
			p.mu.Unlock()
		} else {
			// OnceFunc also joins cancellation's close before releasing the slot.
			w.close()
		}
	}()
	request := frame{Magic: frameMagic, Generation: w.generation, Job: p.sequence.Add(1), Expression: uint32(len(expression)), Body: uint32(len(body)), Limit: uint32(limit)}
	if validate {
		request.Validate = 1
	}
	if err := writeFrame(w.input, request); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w.input, expression); err != nil {
		return nil, err
	}
	if _, err := w.input.Write(body); err != nil {
		return nil, err
	}
	response, err := readFrame(w.output)
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
		result, err = membuffer.Read(io.LimitReader(w.output, int64(response.Body)), int64(response.Body), budget)
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
		if _, err := io.ReadFull(w.output, data); err != nil {
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
	generation uint64
	input      io.WriteCloser
	output     io.ReadCloser
	close      func()
}

func (p *Pool) start() (*worker, error) {
	id := p.sequence.Add(1)
	group, err := createMemoryGroup(p.group.path, strconv.FormatUint(id, 10), WorkerMemory, false)
	if err != nil {
		return nil, err
	}
	command := exec.Command(p.executable, "plugins", "surge", "__jq-worker")
	command.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=96MiB", "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: int(group.file.Fd())}
	input, err := command.StdinPipe()
	if err != nil {
		_ = group.close()
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		_ = group.close()
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		_ = group.close()
		return nil, fmt.Errorf("start memory constrained jq worker: %w", err)
	}
	w := &worker{generation: id, input: input, output: output}
	w.close = sync.OnceFunc(func() {
		_ = command.Process.Kill()
		_ = input.Close()
		_ = output.Close()
		_ = command.Wait()
		_ = group.close()
	})
	return w, nil
}
