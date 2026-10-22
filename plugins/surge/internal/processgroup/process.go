//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package processgroup

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/containerd/cgroups/v3/cgroup2"
)

// Process owns the worker's pipes, process and cgroup. Close joins concurrent
// callers; OOMKilled and Cmd.ProcessState may be read after it returns.
type Process struct {
	Cmd           *exec.Cmd
	Group         *Group
	Input, Output *os.File
	Close         func() error
	OOMKilled     bool
}

// Start takes ownership of cmd's stdin/stdout and starts it in a new worker
// group. Failed cleanup remains owned by the pool and blocks new work.
func (g *Group) Start(cmd *exec.Cmd, limit int64) (process *Process, err error) {
	if err := g.Check(); err != nil {
		return nil, err
	}
	group, err := create(g.Path, rand.Text()[:12], limit, g.root())
	if err != nil {
		return nil, err
	}
	p := &Process{Cmd: cmd, Group: group}
	started := false
	defer func() {
		if !started {
			_ = p.Input.Close()
			_ = p.Output.Close()
			err = errors.Join(err, group.rollback())
		}
	}()
	input, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	p.Input = writer
	defer input.Close()
	reader, output, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	p.Output = reader
	defer output.Close()
	cmd.Stdin, cmd.Stdout = input, output
	// A surviving descendant can keep stderr open after a failed group kill.
	cmd.WaitDelay = cleanupWait
	file, err := os.Open(group.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: int(file.Fd())}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p.Close = sync.OnceValue(func() error {
		var result error
		record := func(operation string, err error) {
			if err != nil {
				result = errors.Join(result, fmt.Errorf("%w: %s %s: %w", ErrCleanup, operation, group.Path, err))
			}
		}
		if err := group.Kill(); err != nil {
			record("kill group", err)
			if err := cmd.Process.Kill(); !errors.Is(err, os.ErrProcessDone) {
				record("kill process", err)
			}
		}
		record("close input", p.Input.Close())
		record("close output", p.Output.Close())
		if err := cmd.Wait(); err != nil {
			if _, exited := errors.AsType[*exec.ExitError](err); !exited {
				record("wait process", err)
			}
		}
		stats, err := group.StatFiltered(cgroup2.StatMemoryEvents)
		record("read memory events", err)
		if err == nil && stats.MemoryEvents != nil {
			p.OOMKilled = stats.MemoryEvents.OomKill != 0
		}
		if result != nil {
			group.remember(result)
		}
		return errors.Join(result, group.Delete())
	})
	started = true
	return p, nil
}
