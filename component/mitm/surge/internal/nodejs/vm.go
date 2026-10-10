//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// VM is a single invocation's lease. Script operations use one goroutine;
// cancellation and pool shutdown may terminate the process concurrently.
// Close joins the cancellation callback before returning the worker for reuse.
type VM struct {
	pool        *Pool
	worker      *worker
	ctx         context.Context
	host        func([]string) (any, error)
	failed      bool
	stop        func() bool
	interrupted chan struct{}
}

func (vm *VM) command(c command) (err error) {
	if int64(len(c.Text)) > vm.pool.memoryLimit {
		return fmt.Errorf("nodejs: %s data exceeds memory limit", c.Op)
	}
	defer func() {
		if vm.ctx.Err() != nil {
			err = vm.ctx.Err()
		}
		if err != nil {
			vm.failed = true
		}
	}()
	if err := vm.ctx.Err(); err != nil {
		return err
	}
	if err := vm.worker.write(c); err != nil {
		return fmt.Errorf("nodejs: send command: %w", err)
	}
	for {
		response, err := vm.worker.read()
		if err != nil {
			vm.worker.close()
			return fmt.Errorf("nodejs: receive worker response: %w (%s)", err, strings.TrimSpace(string(vm.worker.stderr.data)))
		}
		switch response.Kind {
		case "ok":
			return nil
		case "error":
			return fmt.Errorf("nodejs: %s", response.Error)
		case "host":
			value, err := vm.hostCall(response.Args)
			reply := command{Op: "reply", Value: value}
			if err != nil {
				reply.Error = err.Error()
			}
			if err := vm.worker.write(reply); err != nil {
				return fmt.Errorf("nodejs: reply to host call: %w", err)
			}
		default:
			return errors.New("nodejs: invalid worker response")
		}
	}
}

func (vm *VM) hostCall(args []string) (any, error) {
	var size int64
	for _, arg := range args {
		size += int64(len(arg))
	}
	if size > vm.pool.memoryLimit {
		return nil, errors.New("nodejs: host arguments exceed memory limit")
	}
	value, err := vm.host(args)
	if s, ok := value.(string); ok && int64(len(s)) > vm.pool.memoryLimit {
		return nil, errors.New("nodejs: host string exceeds memory limit")
	}
	return value, err
}

func (vm *VM) SetHostFunc(host func([]string) (any, error)) error {
	vm.host = host
	return nil
}

func (vm *VM) SetInputJSON(data []byte) error {
	return vm.command(command{Op: "context", Text: string(data)})
}

func (vm *VM) Bootstrap() error { return vm.command(command{Op: "bootstrap"}) }

func (vm *VM) Eval(source string) error {
	return vm.command(command{Op: "eval", Text: source})
}

func (vm *VM) Dispatch(id int, data string) error {
	return vm.command(command{Op: "dispatch", ID: id, Text: data})
}

// Node drains the context's microtask queue after every evaluation/dispatch.
func (vm *VM) ExecutePendingJobs() error { return vm.ctx.Err() }

func (vm *VM) Close() {
	if vm.worker == nil {
		return
	}
	if !vm.failed {
		_ = vm.command(command{Op: "reset"})
	}
	if !vm.stop() {
		<-vm.interrupted
	}
	p, w := vm.pool, vm.worker
	p.mu.Lock()
	if vm.failed || vm.ctx.Err() != nil || p.closed {
		w.close()
		delete(p.workers, w)
		if !p.closed {
			p.stats.Discarded++
		}
	} else {
		w.idleSince = time.Now()
		p.idle = append(p.idle, w)
	}
	p.mu.Unlock()
	vm.worker, vm.host = nil, nil
	<-p.slots
}
